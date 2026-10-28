/**
 * URL-safety guards in the Electron shell (subscription-store.cjs).
 *
 * Two findings, both about a URL the shell hands onward without checking
 * its shape:
 *  - `safeExternalTarget`: will-navigate and setWindowOpenHandler passed any
 *    off-origin target straight to shell.openExternal, so every scheme
 *    reached the OS handler. The targets can come from model-authored
 *    transcript links, and the subscription openers next door already
 *    checked — the asymmetry was the bug.
 *  - `safeDomain`: a Copilot credential's own enterpriseUrl authorizes its
 *    endpoint, and the check accepted bare IPs, localhost and single labels,
 *    so the stored credential could aim its endpoint — and the Bearer
 *    refresh that happens before any endpoint check — inside the network.
 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { describe, it } from "node:test";

const require = createRequire(import.meta.url);
const { safeExternalTarget, safeDomain, safeHttps } = require("../electron/subscription-store.cjs");

describe("safeExternalTarget", () => {
	it("allows the schemes a transcript link legitimately uses", () => {
		for (const target of [
			"https://example.com/article",
			"http://example.com/article",
			"mailto:teacher@example.com",
			"mailto:teacher@example.com?subject=Lesson",
		]) {
			assert.equal(safeExternalTarget(target), true, target);
		}
	});

	it("refuses the schemes that reach an OS handler or leak credentials", () => {
		for (const target of [
			"file:///etc/passwd",
			"file://attacker.example/share", // NTLM leak on Windows
			"smb://attacker.example/share",
			"ms-msdt:/id PCWDiagnostic",
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
			"vbscript:msgbox(1)",
			"chrome://settings",
			"about:blank",
			"ftp://example.com/x",
			"custom-app://do-something",
		]) {
			assert.equal(safeExternalTarget(target), false, target);
		}
	});

	it("refuses embedded credentials and junk input", () => {
		assert.equal(safeExternalTarget("https://user:pass@example.com"), false);
		for (const target of ["", "not a url", null, undefined, 42, {}]) {
			assert.equal(safeExternalTarget(target as unknown as string), false, String(target));
		}
	});
});

describe("safeDomain for a Copilot enterprise host", () => {
	it("still accepts a real enterprise domain", () => {
		for (const domain of ["company.ghe.com", "ghe.example.co.uk", "sub.domain.example.com"]) {
			assert.equal(safeDomain(domain), true, domain);
		}
	});

	it("refuses anything that points inside the network", () => {
		for (const domain of [
			"localhost",
			"127.0.0.1",
			"10.0.0.1",
			"169.254.169.254",
			"::1",
			"intranet", // single label resolves on the local search domain
			"gateway.local",
			"vault.internal",
			"nas.lan",
			"x.home.arpa",
		]) {
			assert.equal(safeDomain(domain), false, domain);
		}
	});

	it("keeps refusing malformed values", () => {
		for (const domain of ["", "has space.com", "a/b.com", "user@host.com", "host:443", "UPPER.example.com"]) {
			assert.equal(safeDomain(domain), false, domain);
		}
	});
});

describe("safeHttps gates the update feed override", () => {
	it("accepts an https feed and refuses anything weaker", () => {
		assert.equal(safeHttps("https://downloads.example.com/learnharness/"), true);
		// This build requires no publisher signature (owner ruling), so the
		// transport is the only integrity the update has left.
		for (const feed of ["http://downloads.example.com/", "http://127.0.0.1:8080/", "https://user:pass@x.example/", "file:///tmp/feed", "not a url"]) {
			assert.equal(safeHttps(feed), false, feed);
		}
	});
});
