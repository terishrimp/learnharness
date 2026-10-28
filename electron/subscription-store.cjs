"use strict";
const fs = require("node:fs/promises");
const path = require("node:path");
const { randomUUID } = require("node:crypto");

const PROVIDERS = ["anthropic", "github-copilot", "xai"];
const failure = (code) => Object.assign(new Error(code), { code });
const nonempty = (value) => typeof value === "string" && value.length > 0 && !/[\x00-\x20\x7f]/.test(value);
function validateCredential(providerId, credential) {
	if (!credential || credential.type !== "oauth" || !nonempty(credential.access) || !nonempty(credential.refresh) || !Number.isFinite(credential.expires) || credential.expires < 0) throw failure("storage");
	if (providerId === "github-copilot") {
		if (credential.enterpriseUrl !== undefined && !safeDomain(credential.enterpriseUrl)) throw failure("storage");
		if (credential.availableModelIds !== undefined && (!Array.isArray(credential.availableModelIds) || !credential.availableModelIds.every(nonempty))) throw failure("storage");
	}
	return credential;
}
/** Local-only names a public enterprise host can never legitimately be. */
const LOCAL_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa", ".lan"];
function safeDomain(value) {
	if (typeof value !== "string" || !value || /[\s/:@?#\\]/.test(value)) return false;
	// An enterprise domain is a PUBLIC registrable name. Accepting a bare IP,
	// localhost, a single label or a local suffix let the stored credential
	// aim its own endpoint — and the Bearer refresh that precedes any
	// endpoint check — at a host inside the learner's network.
	if (value === "localhost" || !value.includes(".")) return false;
	if (LOCAL_SUFFIXES.some((suffix) => value.toLowerCase().endsWith(suffix))) return false;
	if (require("node:net").isIP(value) !== 0) return false;
	try { return new URL(`https://${value}`).hostname === value; } catch { return false; }
}
function safeHttps(value) {
	try {
		const url = new URL(value);
		return url.protocol === "https:" && !url.username && !url.password;
	} catch { return false; }
}
/** Schemes the app will hand to the OS when the trusted window navigates
 *  away or opens a link. Everything else is refused: `file:`/`smb:` leak
 *  NTLM credentials on Windows, `ms-msdt:` and friends reach OS handlers,
 *  and the targets can come from model-authored transcript links. The
 *  subscription openers next door have always checked; these did not. */
const EXTERNAL_SCHEMES = new Set(["https:", "http:", "mailto:"]);
function safeExternalTarget(value) {
	if (typeof value !== "string" || value.length === 0) return false;
	try {
		const url = new URL(value);
		if (!EXTERNAL_SCHEMES.has(url.protocol)) return false;
		return url.protocol === "mailto:" || (!url.username && !url.password);
	} catch { return false; }
}
function validateState(providerId, state) {
	if (!PROVIDERS.includes(providerId) || !state || state.version !== 1 || typeof state.allowBackgroundUse !== "boolean") throw failure("storage");
	const hasId = Object.hasOwn(state, "connectionId");
	if (hasId !== Object.hasOwn(state, "credential") || (hasId && !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(state.connectionId))) throw failure("storage");
	if (hasId) validateCredential(providerId, state.credential);
	return state;
}
/** Main-process-only, one independent owner-only file per provider. No recovery writes on corruption. */
function fileStore(file, providerId, io = fs) {
	return {
		async read() {
			try {
				const stat = await io.lstat(file);
				if (!stat.isFile() || (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || (typeof process.getuid === "function" && stat.uid !== process.getuid())))) throw failure("storage");
				return validateState(providerId, JSON.parse(await io.readFile(file, "utf8")));
			}
			catch (error) { if (error.code === "ENOENT") return { version: 1, allowBackgroundUse: true }; throw failure("storage"); }
		},
		async write(state) {
			validateState(providerId, state);
			const temporary = `${file}.${randomUUID()}.tmp`;
			let handle;
			try {
				await io.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
				handle = await io.open(temporary, "wx", 0o600);
				await handle.writeFile(`${JSON.stringify(state)}\n`);
				await handle.sync(); await handle.close(); handle = null;
				await io.rename(temporary, file);
				if (process.platform !== "win32") {
					const directory = await io.open(path.dirname(file), "r");
					try { await directory.sync(); } finally { await directory.close(); }
				}
			} catch { throw failure("storage"); }
			finally { await handle?.close().catch(() => {}); await io.unlink(temporary).catch(() => {}); }
		},
	};
}
module.exports = { PROVIDERS, failure, validateCredential, validateState, safeDomain, safeHttps, safeExternalTarget, fileStore };
