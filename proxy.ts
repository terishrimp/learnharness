import { NextResponse, type NextRequest } from "next/server";
import { desktopAPIAuthorized, desktopCapabilityRequired } from "./src/server/desktop-access.ts";
import { crossOriginBrowserRequest } from "./src/server/same-origin.ts";

function refuse(error: string) {
	return NextResponse.json({ error }, { status: 403, headers: { "Cache-Control": "no-store" } });
}

/** Applies to every API method, including SSE and spending/settings routes.
 * No public callback or worker bypass: internal jobs call server functions,
 * and any legitimate self-HTTP request must carry the private capability.
 *
 * Two gates, one per mode. Packaged desktop requires the per-launch
 * capability header, which main.cjs injects only for the trusted window.
 * Ordinary web/dev has no such proof and deliberately admits any client
 * that can reach the port (the documented shared-server trust model) — but
 * that model was never meant to admit a WEBSITE the learner happens to be
 * visiting, which could drive these routes cross-origin with no preflight
 * (see same-origin.ts). Only the subscription routes used to check. */
export function proxy(request: NextRequest) {
	if (!desktopAPIAuthorized(request.headers)) {
		return refuse("Desktop API access requires the trusted LearnHarness window.");
	}
	if (!desktopCapabilityRequired() && crossOriginBrowserRequest(request)) {
		return refuse("LearnHarness API requests must come from the app's own origin.");
	}
	return NextResponse.next();
}

export const config = { matcher: "/api/:path*" };
