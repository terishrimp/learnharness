import { timingSafeEqual } from "node:crypto";

/** Per-launch desktop HTTP capability. This is not an OS-user malware
 * boundary and is not an OAuth credential. Browser-only mode is unchanged. */
/**
 * Is the per-launch capability in force? When it is, a request's provenance
 * is already proven and the proxy needs nothing further; when it is not,
 * `desktopAPIAuthorized` passes everything through and the same-origin rule
 * (same-origin.ts) is the only thing standing between a website the learner
 * visits and these routes. This is the exact complement of the pass-through
 * condition below, kept beside it so the two cannot drift.
 */
export function desktopCapabilityRequired(
	env: Record<string, string | undefined> = process.env,
): boolean {
	return env.LH_DESKTOP_SERVER === "1" || !!env.LH_DESKTOP_API_SECRET;
}

export function desktopAPIAuthorized(
	headers: Headers,
	env: Record<string, string | undefined> = process.env,
): boolean {
	const expected = env.LH_DESKTOP_API_SECRET;
	if (!desktopCapabilityRequired(env)) return true;
	if (!expected || expected.length < 64) return false;
	const supplied = headers.get("x-learnharness-desktop");
	if (!supplied) return false;
	const actual = Buffer.from(supplied);
	const wanted = Buffer.from(expected);
	return actual.length === wanted.length && timingSafeEqual(actual, wanted);
}
