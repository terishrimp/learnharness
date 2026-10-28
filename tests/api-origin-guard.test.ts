/**
 * The web/dev same-origin gate on /api/* (same-origin.ts + proxy.ts).
 *
 * Packaged desktop proves provenance with the per-launch capability header.
 * Ordinary web/dev proves nothing and deliberately admits any client that
 * can reach the port — the documented shared-server trust model. That model
 * covers a LAN peer with curl; it never meant to cover a WEBSITE the learner
 * is visiting, which could drive these routes cross-origin with no
 * preflight. POST /api/graph/import was the sink: multipart/form-data is
 * CORS-safelisted, so a drive-by page could spend the learner's provider
 * credits and merge its own propositions into the knowledge graph.
 *
 * These cases pin the gate: the attack shapes are refused, the app's own
 * traffic and non-browser clients still pass, and desktop mode is untouched.
 */
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { NextRequest } from "next/server";
import { crossOriginBrowserRequest, requestAddressedOrigin } from "../src/server/same-origin.ts";
import { desktopCapabilityRequired } from "../src/server/desktop-access.ts";
import { proxy } from "../proxy.ts";

const APP = "http://localhost:3000";
const ATTACKER = "https://evil.example";

const originalMarker = process.env.LH_DESKTOP_SERVER;
const originalSecret = process.env.LH_DESKTOP_API_SECRET;
afterEach(() => {
	if (originalMarker === undefined) delete process.env.LH_DESKTOP_SERVER;
	else process.env.LH_DESKTOP_SERVER = originalMarker;
	if (originalSecret === undefined) delete process.env.LH_DESKTOP_API_SECRET;
	else process.env.LH_DESKTOP_API_SECRET = originalSecret;
});

/** A request as it reaches the server, Host included. */
function request(path: string, init: { method?: string; headers?: Record<string, string> } = {}) {
	return new NextRequest(APP + path, {
		method: init.method ?? "GET",
		headers: { host: "localhost:3000", ...init.headers },
	});
}
const allowed = (r: NextRequest) => proxy(r).headers.get("x-middleware-next") === "1";

describe("same-origin rule", () => {
	it("refuses what the browser reports as another origin", () => {
		for (const site of ["cross-site", "same-site"]) {
			assert.equal(crossOriginBrowserRequest(request("/api/chats", { headers: { "sec-fetch-site": site } })), true, site);
		}
	});

	it("admits the app's own fetches and the learner's own navigation", () => {
		// same-origin: the renderer calling /api. none: a typed URL or bookmark.
		for (const site of ["same-origin", "none"]) {
			assert.equal(crossOriginBrowserRequest(request("/api/chats", { headers: { "sec-fetch-site": site } })), false, site);
		}
	});

	it("refuses a mismatched Origin even with no Sec-Fetch metadata", () => {
		assert.equal(crossOriginBrowserRequest(request("/api/chats", { headers: { origin: ATTACKER } })), true);
		assert.equal(crossOriginBrowserRequest(request("/api/chats", { headers: { origin: APP } })), false);
	});

	it("refuses an opaque origin, which is how the sandboxed demo iframe presents", () => {
		// The demo runs with sandbox="allow-scripts" and no allow-same-origin,
		// so its requests carry Origin: null — it must not reach the API that
		// reads credentials on its behalf.
		assert.equal(crossOriginBrowserRequest(request("/api/stt/token", { headers: { origin: "null" } })), true);
	});

	it("leaves a non-browser client alone — the shared-server model, unchanged", () => {
		// curl, a LAN peer, or the app's own server-side fetch: no Sec-Fetch,
		// no Origin. The trust model documents these as trusted.
		assert.equal(crossOriginBrowserRequest(request("/api/events")), false);
		assert.equal(crossOriginBrowserRequest(request("/api/chats", { method: "POST" })), false);
	});

	it("derives the addressed origin from Host, and rejects a malformed one", () => {
		assert.equal(requestAddressedOrigin(request("/api/chats")), APP);
		for (const host of ["local host", "user:pass@localhost", ""]) {
			const r = new NextRequest(APP + "/api/chats", { headers: { host } });
			const value = requestAddressedOrigin(r);
			assert.ok(value === undefined || value === APP, `host ${JSON.stringify(host)} -> ${value}`);
		}
	});
});

describe("proxy in web/dev mode", () => {
	it("refuses the graph/import drive-by, the finding's sink", () => {
		// multipart/form-data needs no preflight, so the browser delivers it;
		// the attacker never reads the response, only causes the write.
		const attack = request("/api/graph/import", {
			method: "POST",
			headers: { origin: ATTACKER, "sec-fetch-site": "cross-site", "content-type": "multipart/form-data; boundary=x" },
		});
		const response = proxy(attack);
		assert.equal(response.status, 403);
		assert.equal(allowed(attack), false);
	});

	it("refuses every other no-preflight mutating shape the audit named", () => {
		for (const [path, contentType] of [
			["/api/chats", "text/plain"],
			["/api/graph/coverage/extract", "text/plain"],
			["/api/activity/abort", "text/plain"],
			["/api/chat", "application/x-www-form-urlencoded"],
			["/api/chats/scratch/steer", "text/plain"],
		] as const) {
			const r = request(path, { method: "POST", headers: { origin: ATTACKER, "sec-fetch-site": "cross-site", "content-type": contentType } });
			assert.equal(proxy(r).status, 403, path);
		}
	});

	it("refuses a cross-origin read of the token and transcript routes", () => {
		for (const path of ["/api/stt/token", "/api/chats", "/api/settings", "/api/keys"]) {
			assert.equal(proxy(request(path, { headers: { "sec-fetch-site": "cross-site" } })).status, 403, path);
		}
	});

	it("still admits the app's own requests on every method", () => {
		for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE"]) {
			const r = request("/api/settings", { method, headers: { origin: APP, "sec-fetch-site": "same-origin" } });
			assert.equal(allowed(r), true, method);
		}
		// SSE, as the renderer opens it.
		assert.equal(allowed(request("/api/events", { headers: { "sec-fetch-site": "same-origin" } })), true);
		// The smoke harness's header-less server-side fetch.
		assert.equal(allowed(request("/api/events")), true);
	});
});

describe("desktop mode is untouched", () => {
	it("keeps requiring the capability and ignores origin metadata", () => {
		const secret = "a".repeat(64);
		process.env.LH_DESKTOP_SERVER = "1";
		process.env.LH_DESKTOP_API_SECRET = secret;
		assert.equal(desktopCapabilityRequired(), true);
		// No capability: refused regardless of looking same-origin.
		assert.equal(proxy(request("/api/settings", { headers: { origin: APP, "sec-fetch-site": "same-origin" } })).status, 403);
		// With it: admitted, and the origin rule does not second-guess the
		// capability (main.cjs already pinned the window and initiator).
		assert.equal(allowed(request("/api/settings", { headers: { "x-learnharness-desktop": secret } })), true);
		assert.equal(
			allowed(request("/api/settings", { method: "POST", headers: { "x-learnharness-desktop": secret, "sec-fetch-site": "cross-site" } })),
			true,
			"the capability is the proof in desktop mode",
		);
	});

	it("treats a bare secret with no server marker as capability mode too", () => {
		delete process.env.LH_DESKTOP_SERVER;
		process.env.LH_DESKTOP_API_SECRET = "b".repeat(64);
		assert.equal(desktopCapabilityRequired(), true);
		assert.equal(proxy(request("/api/settings")).status, 403, "fails closed rather than falling back to the origin rule");
	});

	it("is web/dev only when neither marker nor secret is set", () => {
		delete process.env.LH_DESKTOP_SERVER;
		delete process.env.LH_DESKTOP_API_SECRET;
		assert.equal(desktopCapabilityRequired(), false);
	});
});
