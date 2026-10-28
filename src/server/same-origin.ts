/**
 * Same-origin admission for HTTP requests (2026-10-28).
 *
 * In packaged desktop mode the per-launch capability header
 * (desktop-access.ts) proves a request came from the trusted window. In
 * ordinary web/dev there is no such proof, and `desktopAPIAuthorized`
 * deliberately passes everything through — the documented shared
 * developer-server trust model, where anyone who can reach the port is as
 * trusted as the API keys on disk.
 *
 * That model covers a LAN peer with curl. It does NOT cover a browser the
 * learner is already using: any website they visit can issue a no-preflight
 * cross-origin POST to localhost, and `multipart/form-data` is a
 * CORS-safelisted content type, so `POST /api/graph/import` was reachable
 * from a drive-by page — spending the learner's provider credits and merging
 * attacker-authored propositions into the knowledge graph the teacher reads
 * on later turns. The attacker never needs to read a response, so
 * same-origin response blocking does not help.
 *
 * So the rule here refuses what a BROWSER tells us is cross-origin, and
 * stays silent about everything else:
 *  - `Sec-Fetch-Site: cross-site` / `same-site` — the browser's own
 *    statement that this came from elsewhere. Sent by every current engine,
 *    unforgeable by page JS (it is a forbidden header name).
 *  - a mismatched `Origin` — the belt for anything that sends Origin but no
 *    Sec-Fetch metadata. `Origin: null` (an opaque origin, such as the
 *    sandboxed demo iframe) never matches, which is the point.
 *  - neither header present — a non-browser client, which is exactly the
 *    shared-server model, left as it was.
 *
 * What this does NOT do, by the same documented decision: DNS rebinding.
 * After a rebind the page's own origin IS the one it is addressing, so it
 * sends `Sec-Fetch-Site: same-origin` and a matching `Origin`. Closing that
 * needs the expected host pinned to what the server binds, which would
 * break the LAN access the trust model explicitly keeps.
 */

/**
 * The origin a request is ADDRESSED to, from the Host header it carried.
 * Used to decide whether a supplied `Origin` is "the same place", so it is
 * compared against, never trusted as an identity: a request that reaches
 * this server with any Host at all addressed that Host.
 */
export function requestAddressedOrigin(request: Request): string | undefined {
	try {
		const url = new URL(request.url);
		const host = request.headers.get("host") ?? url.host;
		const addressed = new URL(`${url.protocol}//${host}`);
		if (
			!["http:", "https:"].includes(addressed.protocol) ||
			addressed.username ||
			addressed.password ||
			addressed.pathname !== "/" ||
			addressed.search ||
			addressed.hash
		) {
			return;
		}
		return addressed.origin;
	} catch {
		return;
	}
}

/** True when a browser has told us this request came from another origin. */
export function crossOriginBrowserRequest(request: Request): boolean {
	const site = request.headers.get("sec-fetch-site");
	// "same-origin" is the app's own fetches; "none" is the learner typing
	// the URL or opening a bookmark. Both are theirs.
	if (site === "cross-site" || site === "same-site") return true;
	const supplied = request.headers.get("origin");
	if (supplied === null) return false;
	const addressed = requestAddressedOrigin(request);
	return addressed === undefined || supplied !== addressed;
}
