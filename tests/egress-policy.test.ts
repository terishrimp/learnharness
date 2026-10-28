/**
 * The egress policy for the researcher's fetch tools (egress.ts).
 *
 * web_fetch and web_fetch_pdf take a URL chosen by a model whose context is
 * full of untrusted material, and they used to check only the protocol. The
 * host was the agent's: cloud metadata, the learner's intranet, or the
 * harness's own loopback API — which reads credentials on its behalf and
 * answers server-side, where no browser or CORS is in the way.
 *
 * DNS is injected throughout, so these never touch a resolver.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
	assertPublicUrl,
	blockedAddress,
	blockedHostname,
	EgressBlockedError,
	guardedFetch,
	type Resolver,
} from "../src/agent/tools/egress.ts";

const publicDns: Resolver = async () => ["93.184.216.34"];
const never: Resolver = async () => {
	throw new Error("DNS must not be consulted for a literal address");
};

describe("address classification", () => {
	it("refuses every private and special-purpose IPv4 range", () => {
		for (const ip of [
			"127.0.0.1", "127.1.2.3", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.255",
			"192.168.1.1", "169.254.169.254", "100.64.0.6", "192.0.0.1", "192.0.2.5",
			"198.18.0.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		]) {
			assert.ok(blockedAddress(ip), `${ip} must be refused`);
		}
	});

	it("admits ordinary public IPv4", () => {
		for (const ip of ["93.184.216.34", "8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.255.255", "100.63.255.255", "100.128.0.1"]) {
			assert.equal(blockedAddress(ip), null, `${ip} must be allowed`);
		}
	});

	it("refuses IPv6 loopback, unspecified, ULA, link-local and multicast", () => {
		for (const ip of ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1"]) {
			assert.ok(blockedAddress(ip), `${ip} must be refused`);
		}
	});

	it("looks through IPv4-mapped and NAT64 forms, where loopback likes to hide", () => {
		for (const ip of ["::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "64:ff9b::127.0.0.1"]) {
			assert.ok(blockedAddress(ip), `${ip} must be refused`);
		}
		assert.equal(blockedAddress("::ffff:93.184.216.34"), null, "a mapped public address is still public");
	});

	it("admits ordinary public IPv6", () => {
		for (const ip of ["2606:4700:4700::1111", "2001:4860:4860::8888"]) {
			assert.equal(blockedAddress(ip), null, ip);
		}
	});
});

describe("hostname classification", () => {
	it("refuses names that can only mean here", () => {
		for (const host of ["localhost", "LOCALHOST", "localhost.", "foo.localhost", "printer.local", "db.internal", "x.home.arpa", "nas.lan"]) {
			assert.ok(blockedHostname(host), `${host} must be refused`);
		}
	});

	it("admits ordinary public names", () => {
		for (const host of ["example.com", "en.wikipedia.org", "localhost.example.com", "mylocal.com"]) {
			assert.equal(blockedHostname(host), null, host);
		}
	});
});

describe("assertPublicUrl", () => {
	it("refuses a non-http scheme", async () => {
		for (const url of ["file:///etc/passwd", "ftp://example.com", "gopher://example.com"]) {
			await assert.rejects(() => assertPublicUrl(url, publicDns), EgressBlockedError, url);
		}
	});

	it("refuses the exact targets the audit named", async () => {
		// Cloud metadata, the app's own API, and an intranet host.
		for (const url of [
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			"http://127.0.0.1:3000/api/chats",
			"http://localhost:3000/api/stt/token",
			"http://[::1]:3000/api/keys",
			"http://10.0.0.1/admin",
		]) {
			await assert.rejects(() => assertPublicUrl(url, never), EgressBlockedError, url);
		}
	});

	it("refuses a public NAME that resolves somewhere private", async () => {
		const rebind: Resolver = async () => ["127.0.0.1"];
		await assert.rejects(() => assertPublicUrl("https://evil.example/", rebind), EgressBlockedError);
	});

	it("refuses a name with ANY private record, so a mixed answer cannot smuggle one", async () => {
		const mixed: Resolver = async () => ["93.184.216.34", "169.254.169.254"];
		await assert.rejects(() => assertPublicUrl("https://evil.example/", mixed), EgressBlockedError);
	});

	it("refuses a name that does not resolve at all", async () => {
		await assert.rejects(() => assertPublicUrl("https://nx.example/", async () => []), EgressBlockedError);
		await assert.rejects(
			() => assertPublicUrl("https://nx.example/", async () => { throw new Error("NXDOMAIN"); }),
			EgressBlockedError,
		);
	});

	it("admits a genuine public page", async () => {
		const url = await assertPublicUrl("https://example.com/article?x=1", publicDns);
		assert.equal(url.hostname, "example.com");
	});
});

describe("guardedFetch redirects", () => {
	/** A fetch stand-in driven by a scripted list of responses. */
	function scripted(steps: ({ status: number; location?: string })[]) {
		const seen: string[] = [];
		let index = 0;
		const impl = (async (input: string | URL) => {
			seen.push(String(input));
			const step = steps[Math.min(index++, steps.length - 1)]!;
			return new Response(null, {
				status: step.status,
				headers: step.location ? { location: step.location } : {},
			});
		}) as unknown as typeof fetch;
		return { impl, seen };
	}

	it("refuses a redirect into loopback — the original rule's real hole", async () => {
		const { impl, seen } = scripted([{ status: 302, location: "http://127.0.0.1:3000/api/chats" }]);
		await assert.rejects(
			() => guardedFetch("https://example.com/r", {}, { resolve: publicDns, fetchImpl: impl }),
			EgressBlockedError,
		);
		assert.equal(seen.length, 1, "the private hop is never requested");
	});

	it("refuses a redirect to metadata and to a private name", async () => {
		for (const location of ["http://169.254.169.254/latest/", "http://10.0.0.5/", "file:///etc/passwd"]) {
			const { impl } = scripted([{ status: 302, location }]);
			await assert.rejects(
				() => guardedFetch("https://example.com/r", {}, { resolve: publicDns, fetchImpl: impl }),
				EgressBlockedError,
				location,
			);
		}
	});

	it("follows public redirects and returns the final response", async () => {
		const { impl, seen } = scripted([
			{ status: 302, location: "https://example.com/second" },
			{ status: 200 },
		]);
		const response = await guardedFetch("https://example.com/first", {}, { resolve: publicDns, fetchImpl: impl });
		assert.equal(response.status, 200);
		assert.deepEqual(seen, ["https://example.com/first", "https://example.com/second"]);
	});

	it("stops a redirect loop", async () => {
		const { impl } = scripted([{ status: 302, location: "https://example.com/loop" }]);
		await assert.rejects(
			() => guardedFetch("https://example.com/loop", {}, { resolve: publicDns, fetchImpl: impl }),
			/too many redirects/,
		);
	});

	it("resolves a relative Location against the current hop", async () => {
		const { impl, seen } = scripted([{ status: 301, location: "/moved" }, { status: 200 }]);
		await guardedFetch("https://example.com/old", {}, { resolve: publicDns, fetchImpl: impl });
		assert.deepEqual(seen, ["https://example.com/old", "https://example.com/moved"]);
	});
});
