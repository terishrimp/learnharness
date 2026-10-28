/**
 * The demo document policy and the --browser-service helper's guards.
 *
 * A demo's HTML is model output built from a free-text brief, and it runs
 * twice: in the app's own Chromium during run_demo, and in the learner's
 * window after. The helper window that runs it never reaches createWindow()'s
 * posture, so without its own guards Electron's no-handler default GRANTS
 * permission requests in an invisible window. These cases pin both halves —
 * the live spawn→connect→run chain is a dev-machine exercise
 * (tests/browser-service.test.ts), so the parts that can be pinned are.
 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { describe, it } from "node:test";
import { DEMO_CSP, DEMO_CDN_ORIGINS, withDemoCSP } from "../src/core/contracts/jobs.ts";
import { chromeFallbackArgs } from "../src/agent/subagents/headless.ts";
import { buildDemoSrcDoc } from "../components/artifacts/demo-card.tsx";

const require = createRequire(import.meta.url);
const { applyBrowserServiceGuards, allowedHelperTarget } = require("../electron/browser-service-window.cjs");

describe("demo document policy", () => {
	it("closes the egress a demo never needed", () => {
		// These two directives are the finding: connect-src carried the
		// fetch exfiltration, img-src the new Image().src variant.
		assert.match(DEMO_CSP, /connect-src 'none'/);
		assert.match(DEMO_CSP, /img-src data: blob:/);
		assert.ok(!/img-src[^;]*https?:/.test(DEMO_CSP), "img-src must not admit a remote host");
		assert.match(DEMO_CSP, /default-src 'none'/);
		for (const directive of ["object-src 'none'", "frame-src 'none'", "base-uri 'none'", "form-action 'none'"]) {
			assert.ok(DEMO_CSP.includes(directive), directive);
		}
	});

	it("keeps what the builder's instructions promise: inline code and pinned CDN libraries", () => {
		const script = DEMO_CSP.split("; ").find((d) => d.startsWith("script-src "))!;
		assert.match(script, /'unsafe-inline'/, "the model writes inline JS");
		for (const origin of DEMO_CDN_ORIGINS) assert.ok(script.includes(origin), origin);
		const style = DEMO_CSP.split("; ").find((d) => d.startsWith("style-src "))!;
		assert.match(style, /'unsafe-inline'/);
	});

	it("lands after the doctype, so the document keeps standards mode", () => {
		const out = withDemoCSP('<!doctype html><html><head><title>t</title></head><body>x</body></html>');
		assert.match(out, /^<!doctype html>/i);
		assert.ok(out.indexOf("Content-Security-Policy") < out.indexOf("<title>"), "policy precedes content it governs");
	});

	it("covers a document with no head, and a bare fragment", () => {
		const noHead = withDemoCSP("<!doctype html><html><body>x</body></html>");
		assert.match(noHead, /^<!doctype html>/i);
		assert.match(noHead, /Content-Security-Policy/);
		assert.ok(noHead.indexOf("Content-Security-Policy") < noHead.indexOf("<body>"));

		const fragment = withDemoCSP("<div>fragment demo</div>");
		assert.ok(fragment.startsWith("<meta http-equiv"), "a fragment gets the policy first");
		assert.match(fragment, /<div>fragment demo<\/div>/);
	});

	it("is idempotent, so verification then render cannot stack duplicates", () => {
		const once = withDemoCSP("<!doctype html><html><head></head><body>x</body></html>");
		assert.equal(withDemoCSP(once), once);
		assert.equal(once.match(/Content-Security-Policy/g)?.length, 1);
	});

	it("applies to the learner's iframe too, alongside the bridge script", () => {
		const srcDoc = buildDemoSrcDoc('<!doctype html><html><head></head><body><canvas id="c"></canvas></body></html>');
		assert.match(srcDoc, /Content-Security-Policy/);
		assert.match(srcDoc, /demo-resize/, "the bridge is still injected");
		assert.equal(srcDoc.match(/Content-Security-Policy/g)?.length, 1);
	});
});

describe("chrome fallback sandbox", () => {
	it("keeps the renderer sandbox on by default", () => {
		const args = chromeFallbackArgs({});
		assert.ok(!args.includes("--no-sandbox"), "model-authored HTML must not run unsandboxed");
		assert.ok(args.includes("--disable-gpu") && args.includes("--disable-dev-shm-usage"));
	});

	it("allows an explicit opt-out for environments that cannot start it", () => {
		assert.ok(chromeFallbackArgs({ LH_CHROME_NO_SANDBOX: "1" }).includes("--no-sandbox"));
		// Only the exact opt-in; a stray value does not disable the sandbox.
		assert.ok(!chromeFallbackArgs({ LH_CHROME_NO_SANDBOX: "0" }).includes("--no-sandbox"));
		assert.ok(!chromeFallbackArgs({ LH_CHROME_NO_SANDBOX: "true" }).includes("--no-sandbox"));
	});
});

describe("browser-service helper guards", () => {
	/** Fakes standing in for the helper's BrowserWindow and session. */
	function harness() {
		const handlers = new Map<string, (event: { preventDefault(): void }, target: string) => void>();
		let permissionRequest: ((wc: unknown, p: string, cb: (ok: boolean) => void) => void) | null = null;
		let permissionCheck: ((wc: unknown, p: string, origin: string) => boolean) | null = null;
		let windowOpen: (() => { action: string }) | null = null;
		const win = {
			webContents: {
				on(name: string, fn: (event: { preventDefault(): void }, target: string) => void) { handlers.set(name, fn); },
				setWindowOpenHandler(fn: () => { action: string }) { windowOpen = fn; },
			},
		};
		const session = {
			setPermissionRequestHandler(fn: (wc: unknown, p: string, cb: (ok: boolean) => void) => void) { permissionRequest = fn; },
			setPermissionCheckHandler(fn: (wc: unknown, p: string, origin: string) => boolean) { permissionCheck = fn; },
		};
		applyBrowserServiceGuards({ win, session });
		/** Did the guard block this navigation? */
		const navigates = (name: string, target: string) => {
			let prevented = false;
			handlers.get(name)!({ preventDefault: () => { prevented = true; } }, target);
			return !prevented;
		};
		return {
			navigates,
			askPermission: (p: string) => {
				let granted: boolean | undefined;
				permissionRequest!(null, p, (ok) => { granted = ok; });
				return granted;
			},
			checkPermission: (p: string) => permissionCheck!(null, p, "file://"),
			openWindow: () => windowOpen!(),
			installed: [...handlers.keys()],
		};
	}

	it("denies every permission request — the auto-grant was the finding", () => {
		const h = harness();
		// media is the sharp one: getUserMedia in an invisible window, on a
		// file:// page, which Chromium treats as a secure context.
		for (const permission of ["media", "geolocation", "notifications", "clipboard-read", "midi", "display-capture"]) {
			assert.equal(h.askPermission(permission), false, `request: ${permission}`);
			assert.equal(h.checkPermission(permission), false, `check: ${permission}`);
		}
	});

	it("denies window.open outright rather than handing it to the real browser", () => {
		assert.deepEqual(harness().openWindow(), { action: "deny" });
	});

	it("guards both top-level and subframe navigation", () => {
		assert.deepEqual(harness().installed, ["will-navigate", "will-frame-navigate"]);
	});

	it("permits the demo document and its blank page, refuses anything remote", () => {
		const h = harness();
		for (const name of ["will-navigate", "will-frame-navigate"]) {
			assert.equal(h.navigates(name, "about:blank"), true, `${name}: about:blank`);
			assert.equal(h.navigates(name, "file:///tmp/lh-demo-x/demo.html"), true, `${name}: demo file`);
			for (const target of [
				"https://attacker.example/steal",
				"http://127.0.0.1:3000/api/chats",
				"ms-msdt:/id",
				"smb://attacker.example/share",
				"javascript:alert(1)",
				"not a url",
				"",
			]) {
				assert.equal(h.navigates(name, target), false, `${name}: ${target}`);
			}
		}
	});

	it("classifies targets the same way when asked directly", () => {
		assert.equal(allowedHelperTarget("file:///x/demo.html"), true);
		assert.equal(allowedHelperTarget("https://example.com"), false);
		assert.equal(allowedHelperTarget(undefined), false);
	});
});
