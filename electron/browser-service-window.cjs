"use strict";
/**
 * Guards for the --browser-service helper window (2026-10-28).
 *
 * main.cjs splits on `--browser-service` BEFORE main(), so the helper never
 * reaches createWindow() and never inherited any of its posture: no
 * permission handler, no window-open handler, no navigation guard. Electron's
 * documented default with no permission handler is to GRANT, and the helper
 * is precisely where agent-authored demo HTML executes — the one window in
 * the app that renders model output as a live document. A demo could request
 * camera and microphone and be auto-approved, in an invisible window.
 *
 * The helper's posture is stricter than the app window's, because nothing it
 * loads is ever trusted: every permission is denied (the app window grants
 * media for dictation; a demo has no such need), window.open is denied
 * outright rather than handed to the real browser, and navigation is pinned
 * to the local demo document.
 *
 * Kept separate from main.cjs so the policy is unit-testable with fakes —
 * the live spawn→connect→run chain is exercised on dev machines, not in the
 * suite (see tests/browser-service.test.ts), so the parts that CAN be pinned
 * are worth pinning.
 */

/** The only navigations the helper has any reason to perform: its initial
 *  blank page, and the file:// demo documents runDemo writes to a temp dir.
 *  Anything else — http(s), or a custom scheme aimed at an OS handler — is a
 *  demo trying to leave its document, so it is refused. */
function allowedHelperTarget(target) {
	if (typeof target !== "string" || target.length === 0) return false;
	try {
		const { protocol } = new URL(target);
		return protocol === "file:" || protocol === "about:";
	} catch {
		return false;
	}
}

/**
 * Install the guards. `win` and `session` are injected so tests can pass
 * fakes; in main.cjs they are the helper's BrowserWindow and
 * session.defaultSession.
 */
function applyBrowserServiceGuards({ win, session }) {
	// Deny-by-default, both handlers: the request path covers a live prompt,
	// the check path covers Permissions.query and the auto-grant Electron
	// would otherwise apply. No allowlist — a demo needs no device access.
	session.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
	session.setPermissionCheckHandler(() => false);

	const contents = win.webContents;
	// Never hand a demo's window.open to the real browser (the app window
	// does that for the learner's own link clicks; this is model output).
	contents.setWindowOpenHandler(() => ({ action: "deny" }));

	const guard = (event, target) => {
		if (!allowedHelperTarget(target)) event.preventDefault();
	};
	contents.on("will-navigate", guard);
	// Subframes too: frame-src 'none' in the demo CSP already blocks nested
	// documents, but the guard must not depend on the CSP holding.
	contents.on("will-frame-navigate", guard);
}

module.exports = { applyBrowserServiceGuards, allowedHelperTarget };
