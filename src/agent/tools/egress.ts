import { isIP } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";

/**
 * EGRESS POLICY for the researcher's fetch tools (2026-10-28).
 *
 * `web_fetch` and `web_fetch_pdf` take a URL chosen by a model whose context
 * is filled with untrusted material, and they checked only the protocol. The
 * host was entirely the agent's: an injected turn could read the cloud
 * metadata service, sweep the learner's intranet, or — the sharpest one —
 * address the harness's OWN API on loopback, which reads credentials on its
 * behalf and answers server-side where no browser or CORS stands in the way.
 *
 * So a fetch is allowed only to a PUBLIC address:
 *  - the scheme must be http(s) (unchanged);
 *  - names that only ever mean "here" are refused before any lookup;
 *  - every address the name resolves to must be public — if ANY record is
 *    private the fetch is refused, so a round-robin or multi-record answer
 *    cannot smuggle one through;
 *  - redirects are followed BY HAND, re-running the whole check on each hop,
 *    because the original rule's real weakness was that an allowed public
 *    host could simply answer `302 Location: http://127.0.0.1:3000/api/...`.
 *
 * Residual, and inherent to this approach: DNS is resolved here and again by
 * the connection, so a name that changes answers between the two can still
 * slip past (classic TOCTOU/rebinding). Closing it means pinning the
 * connection to the checked address, which breaks TLS name validation
 * unless the agent dials the IP with its own SNI — more machinery than this
 * is worth, and a rebinding attacker who already controls the model's
 * context has cheaper options.
 */

/** Parse dotted-quad IPv4 to a 32-bit number, or null. */
function ipv4ToInt(ip: string): number | null {
	const parts = ip.split(".");
	if (parts.length !== 4) return null;
	let value = 0;
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return null;
		const byte = Number(part);
		if (byte > 255) return null;
		value = value * 256 + byte;
	}
	return value;
}

/** CIDR blocks that never belong to a public web host. */
const BLOCKED_V4: readonly [string, number, string][] = [
	["0.0.0.0", 8, "this host"],
	["10.0.0.0", 8, "private network"],
	["100.64.0.0", 10, "carrier NAT"],
	["127.0.0.0", 8, "loopback"],
	["169.254.0.0", 16, "link-local (cloud metadata)"],
	["172.16.0.0", 12, "private network"],
	["192.0.0.0", 24, "IETF protocol assignment"],
	["192.0.2.0", 24, "documentation"],
	["192.168.0.0", 16, "private network"],
	["198.18.0.0", 15, "benchmarking"],
	["198.51.100.0", 24, "documentation"],
	["203.0.113.0", 24, "documentation"],
	["224.0.0.0", 4, "multicast"],
	["240.0.0.0", 4, "reserved"],
];

function blockedV4(ip: string): string | null {
	const value = ipv4ToInt(ip);
	if (value === null) return null;
	if (value === 0xffffffff) return "broadcast";
	for (const [base, bits, reason] of BLOCKED_V4) {
		const baseValue = ipv4ToInt(base)!;
		// >>> 0 keeps the mask unsigned; a /0 mask would shift by 32 (a no-op
		// in JS) but no block here uses one.
		const mask = (0xffffffff << (32 - bits)) >>> 0;
		if ((value & mask) >>> 0 === baseValue) return reason;
	}
	return null;
}

/** Expand an IPv6 literal to its eight 16-bit groups, or null. */
function ipv6Groups(ip: string): number[] | null {
	let text = ip.toLowerCase().replace(/^\[|\]$/g, "").split("%")[0]!;
	// A trailing IPv4 (v4-mapped, NAT64) becomes two groups.
	const v4 = text.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
	if (v4) {
		const value = ipv4ToInt(v4[1]!);
		if (value === null) return null;
		text = text.slice(0, v4.index) + [(value >>> 16) & 0xffff, value & 0xffff].map((g) => g.toString(16)).join(":");
	}
	const [head, tail, ...rest] = text.split("::");
	if (rest.length > 0) return null;
	const parse = (part: string | undefined) =>
		part && part.length > 0 ? part.split(":").map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN)) : [];
	const left = parse(head);
	const right = parse(tail);
	if ([...left, ...right].some(Number.isNaN)) return null;
	if (tail === undefined) return left.length === 8 ? left : null;
	const fill = 8 - left.length - right.length;
	if (fill < 0) return null;
	return [...left, ...Array.from({ length: fill }, () => 0), ...right];
}

function blockedV6(ip: string): string | null {
	const groups = ipv6Groups(ip);
	if (!groups) return null;
	const [a = 0, b = 0, c = 0, d = 0, e = 0, f = 0] = groups;
	// v4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::/96) carry an IPv4
	// address: classify the embedded one, or loopback could arrive as
	// ::ffff:127.0.0.1 and pass.
	const embedded = `${(groups[6]! >>> 8) & 0xff}.${groups[6]! & 0xff}.${(groups[7]! >>> 8) & 0xff}.${groups[7]! & 0xff}`;
	if (a === 0 && b === 0 && c === 0 && d === 0 && e === 0 && f === 0xffff) return blockedV4(embedded) ?? null;
	if (a === 0x64 && b === 0xff9b && c === 0 && d === 0 && e === 0 && f === 0) return blockedV4(embedded) ?? "NAT64";
	if (groups.every((g) => g === 0)) return "unspecified";
	if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return "loopback";
	if ((a & 0xfe00) === 0xfc00) return "unique local";
	if ((a & 0xffc0) === 0xfe80) return "link-local";
	if ((a & 0xff00) === 0xff00) return "multicast";
	return null;
}

/** Why this literal address is not a public web host, or null if it is. */
export function blockedAddress(ip: string): string | null {
	const version = isIP(ip);
	if (version === 4) return blockedV4(ip);
	if (version === 6) return blockedV6(ip);
	return null;
}

/** Names that can only mean "this machine" or "this network". */
const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa", ".lan"];

/** Why this hostname is refused before any lookup, or null. */
export function blockedHostname(host: string): string | null {
	const name = host.toLowerCase().replace(/\.$/, "");
	if (name.length === 0) return "empty host";
	if (name === "localhost") return "loopback";
	if (BLOCKED_SUFFIXES.some((suffix) => name.endsWith(suffix))) return "local network name";
	return blockedAddress(name.replace(/^\[|\]$/g, ""));
}

export type Resolver = (host: string) => Promise<string[]>;

const resolveAll: Resolver = async (host) => {
	const records = await dnsLookup(host, { all: true, verbatim: true });
	return records.map((record) => record.address);
};

/**
 * Thrown for a target the policy refuses; the tools turn it into text.
 *
 * `kind` separates a malformed or wrong-scheme URL — which the tools have
 * always reported as "invalid URL", and whose wording their tests pin —
 * from a POLICY refusal, the genuinely new category. The model benefits
 * from the distinction too: "your URL was wrong" and "that destination is
 * off limits" call for different next moves.
 */
export type EgressBlockKind = "invalid" | "scheme" | "policy";
export class EgressBlockedError extends Error {
	constructor(message: string, readonly kind: EgressBlockKind = "policy") {
		super(message);
	}
	/** True for a caller-fixable URL problem rather than a refused target. */
	get malformed(): boolean {
		return this.kind === "invalid" || this.kind === "scheme";
	}
}

/**
 * Check one URL. Returns the parsed URL, or throws EgressBlockedError.
 * `resolve` is injectable so tests never touch DNS.
 */
export async function assertPublicUrl(raw: string, resolve: Resolver = resolveAll): Promise<URL> {
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		throw new EgressBlockedError(`invalid URL "${raw}"`, "invalid");
	}
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		throw new EgressBlockedError("only http(s) URLs are supported", "scheme");
	}
	const named = blockedHostname(url.hostname);
	if (named) throw new EgressBlockedError(`refusing ${url.hostname}: ${named} address`);
	// A literal address needs no lookup; it was already classified above.
	if (isIP(url.hostname.replace(/^\[|\]$/g, "")) !== 0) return url;
	let addresses: string[];
	try {
		addresses = await resolve(url.hostname);
	} catch {
		throw new EgressBlockedError(`could not resolve ${url.hostname}`);
	}
	if (addresses.length === 0) throw new EgressBlockedError(`could not resolve ${url.hostname}`);
	for (const address of addresses) {
		const reason = blockedAddress(address);
		// ANY private record refuses the whole name: a resolver that answers
		// with a mix must not be usable as a smuggling channel.
		if (reason) throw new EgressBlockedError(`refusing ${url.hostname}: resolves to a ${reason} address`);
	}
	return url;
}

const MAX_REDIRECTS = 5;

/**
 * Fetch with the policy applied to the target AND to every redirect hop.
 * Redirects are manual for exactly that reason: `redirect: "follow"` let an
 * allowed public host hand back `Location: http://127.0.0.1:…` and the
 * original check never saw it.
 */
export async function guardedFetch(
	raw: string,
	init: RequestInit = {},
	options: { resolve?: Resolver; fetchImpl?: typeof fetch } = {},
): Promise<Response> {
	const call = options.fetchImpl ?? fetch;
	let target = await assertPublicUrl(raw, options.resolve);
	for (let hop = 0; ; hop++) {
		const response = await call(target, { ...init, redirect: "manual" });
		const location = response.headers.get("location");
		if (![301, 302, 303, 307, 308].includes(response.status) || !location) return response;
		if (hop >= MAX_REDIRECTS) throw new EgressBlockedError("too many redirects");
		let next: string;
		try {
			next = new URL(location, target).toString();
		} catch {
			throw new EgressBlockedError("invalid redirect target");
		}
		target = await assertPublicUrl(next, options.resolve);
	}
}
