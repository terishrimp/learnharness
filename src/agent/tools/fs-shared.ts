import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

/**
 * Shared plumbing for the learner-filesystem tools (ls / find / grep) —
 * sources v1 (2026-09-19): the agent locates and reads the learner's files
 * itself, so paths need no UI affordance (user decision: no attachments —
 * the learner references files in messages; the agent finds them).
 *
 * Safety posture (user-locked): READ-ONLY by construction — no shell-out,
 * no user-controlled process args, no mutation APIs anywhere here. The one
 * deliberate scope widening vs pi: relative paths and default roots resolve
 * against the LEARNER'S HOME, not a project cwd — the harness has no
 * meaningful working directory, and "find my notes" should just work.
 *
 * Ported behaviors (mirroring pi's dist/core/tools/{ls,find,grep}.js): the
 * schemas, descriptions, output formats, and truncation notices are copied
 * verbatim except where semantics differ (home default, no .gitignore —
 * replaced by hard noise exclusions).
 */

/** 50KB — pi's DEFAULT_MAX_BYTES, the output ceiling for every fs tool. */
export const MAX_OUTPUT_BYTES = 50 * 1024;
/** pi's grep line-truncation length (GREP_MAX_LINE_LENGTH). */
export const GREP_MAX_LINE_LENGTH = 500;
/** Wall-clock budget for tree walks (find/grep over a whole home dir). */
export const WALK_TIMEOUT_MS = 10_000;

/**
 * Directory names never entered during walks. node_modules/.git mirror pi's
 * fd/rg defaults; Library/.Trash are the home-root noise the user approved
 * (2026-09-19) — caches, app support, and the trash live under them.
 * Explicit paths (ls/read of ~/Library/…) are NOT filtered — only walks.
 */
const EXCLUDED_DIR_NAMES = new Set(["node_modules", ".git", "Library", ".Trash"]);

/**
 * THE READABLE SCOPE (2026-10-28). The fs tools are driven by a model whose
 * context holds untrusted material — fetched pages, learner PDFs — and they
 * auto-execute with no approval step, so "unrestricted local reads" made an
 * injected turn a credential reader: one `read` of the BYOK key map or a
 * `grep` for `sk-…` over the profile and the keys are in the transcript.
 * Every fs tool and the pdf job resolve through here, so this is the one
 * gate that covers all of them.
 *
 * Two rules, both enforced on the symlink-resolved path:
 *  - CONTAINMENT: the target must sit under an allowed root. Home stays the
 *    anchor (relative paths already resolved there); LH_FS_ROOTS adds more,
 *    path-delimited, for notes on another drive — the same env-seam idiom as
 *    LH_DATA_DIR/LH_AUTH_FILE in config.ts.
 *  - SECRET STORES: credential files and key directories are refused even
 *    inside a root. Matched BY NAME, not by absolute path, so the desktop
 *    userData copy and the dev repo-root copy are both covered without this
 *    module importing config (the agent layer owns no paths).
 *
 * Refusal is indistinguishable from absence on purpose: one message for
 * out-of-root and denied alike, so probing cannot map the filesystem.
 */
const DENIED_DIR_NAMES = new Set([".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gh"]);
/** auth.json (the BYOK map), the per-provider OAuth stores, dotenv files,
 *  and the classic token-bearing dotfiles. */
const DENIED_FILE_NAMES =
	/^(auth\.json|.+-credentials\.json|\.env(\..+)?|\.netrc|\.npmrc|\.pypirc|\.git-credentials)$/i;
const OUT_OF_SCOPE =
	"Path is outside the readable scope: the learner's home directory, excluding credential and key stores. " +
	"Ask the learner to paste the contents instead, or have them set LH_FS_ROOTS to add a readable root.";

/** Windows and macOS compare paths case-insensitively; Linux does not. */
const FOLD_CASE = process.platform === "win32" || process.platform === "darwin";
const comparable = (p: string) => (FOLD_CASE ? p.toLowerCase() : p);

/**
 * Home plus any LH_FS_ROOTS entries, each in BOTH its declared and its
 * symlink-resolved form. Both forms are needed because the target is also
 * checked resolved, and the two spellings of one directory routinely differ:
 * macOS resolves /var/folders (tmpdir) to /private/var/folders, and Windows
 * hands out 8.3 short names (C:\Users\TERENC~1\…) that expand to the long
 * path. Comparing a resolved target against an unresolved root rejects the
 * learner's own files.
 *
 * Read per call so a test or a relaunch can set the seam without reloading
 * the module.
 */
async function allowedRoots(): Promise<string[]> {
	const declared = [
		os.homedir(),
		...(process.env.LH_FS_ROOTS ?? "").split(path.delimiter).map((entry) => entry.trim()).filter(Boolean),
	];
	const roots = new Set<string>();
	for (const entry of declared) {
		const resolved = path.resolve(entry);
		roots.add(resolved);
		roots.add(await symlinkResolved(resolved));
	}
	return [...roots];
}

function withinRoot(target: string, roots: readonly string[]): boolean {
	const candidate = comparable(target);
	return roots.some((root) => {
		const base = comparable(root);
		const prefix = base.endsWith(path.sep) ? base : base + path.sep;
		return candidate === base || candidate.startsWith(prefix);
	});
}

function isSecretStore(target: string): boolean {
	const segments = target.split(/[\\/]+/).filter(Boolean);
	// `.config/gh` is a two-segment name; check joined pairs alongside singles.
	for (let i = 0; i < segments.length; i++) {
		const one = segments[i]!.toLowerCase();
		if (DENIED_DIR_NAMES.has(one)) return true;
		const next = segments[i + 1];
		if (next && DENIED_DIR_NAMES.has(`${one}/${next.toLowerCase()}`)) return true;
	}
	const name = segments.at(-1);
	return name !== undefined && DENIED_FILE_NAMES.test(name);
}

/** Resolve symlinks as far as the path exists, then re-apply the rules to
 *  the real target — a link inside a root cannot aim at a secret store or
 *  outside the roots. A not-yet-existing path resolves lexically and the
 *  caller's own stat/read reports its absence, as before. */
async function symlinkResolved(target: string): Promise<string> {
	let head = target;
	const tail: string[] = [];
	for (;;) {
		try {
			return path.join(await fs.realpath(head), ...[...tail].reverse());
		} catch {
			const parent = path.dirname(head);
			if (parent === head) return target;
			tail.push(path.basename(head));
			head = parent;
		}
	}
}

/** Resolve a tool path argument: absolute stays, relative/absent → home,
 *  then the readable-scope rules above. Throws for anything out of scope. */
export async function resolveSourcePath(p?: string): Promise<string> {
	const resolved = p
		? path.isAbsolute(p)
			? path.resolve(p)
			: path.resolve(os.homedir(), p)
		: path.resolve(os.homedir());
	// Check the lexical target AND its symlink-resolved form; either failing
	// is a refusal, so a link cannot launder a denied destination.
	const roots = await allowedRoots();
	for (const candidate of new Set([resolved, await symlinkResolved(resolved)])) {
		if (!withinRoot(candidate, roots) || isSecretStore(candidate)) throw new Error(OUT_OF_SCOPE);
	}
	return resolved;
}

/** pi's formatSize idiom (50KB prints as "50.0KB"). */
export function formatSize(bytes: number): string {
	return bytes >= 1024 ? `${(bytes / 1024).toFixed(1)}KB` : `${bytes}B`;
}

/** Cap output to MAX_OUTPUT_BYTES on whole lines, pi's truncateHead idiom. */
export function capOutput(lines: string[]): { content: string; truncated: boolean } {
	const out: string[] = [];
	for (const line of lines) {
		const candidate = [...out, line].join("\n");
		if (Buffer.byteLength(candidate, "utf-8") > MAX_OUTPUT_BYTES) {
			return { content: out.join("\n"), truncated: true };
		}
		out.push(line);
	}
	return { content: out.join("\n"), truncated: false };
}

/** Expand top-level brace alternatives: '*.{ts,tsx}' → ['*.ts', '*.tsx'].
 *  Nested braces are out of scope (pi's fd handles them; models rarely
 *  emit them — a non-expanding literal match is the graceful fallback). */
export function expandBraces(pattern: string): string[] {
	const open = pattern.indexOf("{");
	if (open === -1) return [pattern];
	const close = pattern.indexOf("}", open);
	if (close === -1) return [pattern];
	const before = pattern.slice(0, open);
	const after = pattern.slice(close + 1);
	const alts: string[] = [];
	for (const alt of pattern.slice(open + 1, close).split(",")) {
		alts.push(...expandBraces(before + alt + after));
	}
	return alts;
}

/** Glob → anchored RegExp. '*' stays within a segment, '**' crosses '/',
 *  '?' is one char, everything else literal. */
export function globToRegex(glob: string): RegExp {
	let re = "";
	for (let i = 0; i < glob.length; i++) {
		const c = glob[i]!;
		if (c === "*") {
			if (glob[i + 1] === "*") {
				re += "[\\s\\S]*";
				i++;
				if (glob[i + 1] === "/") i++; // '**/' also eats the slash
			} else {
				re += "[^/]*";
			}
		} else if (c === "?") {
			re += "[^/]";
		} else {
			re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		}
	}
	return new RegExp(`^${re}$`);
}

/**
 * pi/fd's matching rule: a pattern with no slash matches against the
 * BASENAME at any depth; one with a slash matches the relative path, with
 * an implied leading "**-slash" prefix unless it is itself anchored (see
 * the code below — the literal sequence cannot appear in this comment
 * because it terminates block comments).
 */
export function matchGlob(relativePath: string, pattern: string): boolean {
	const posix = relativePath.split(path.sep).join("/");
	const basename = posix.split("/").pop() ?? posix;
	for (const alt of expandBraces(pattern)) {
		if (!alt.includes("/")) {
			if (globToRegex(alt).test(basename)) return true;
		} else {
			let effective = alt;
			if (!effective.startsWith("/") && !effective.startsWith("**/") && effective !== "**") {
				effective = `**/${effective}`;
			}
			if (effective.startsWith("/")) effective = effective.slice(1);
			if (globToRegex(effective).test(posix)) return true;
		}
	}
	return false;
}

/**
 * Depth-first walk under `root`, never entering EXCLUDED_DIR_NAMES.
 * `visit` receives absolute file paths; returning true STOPS the walk
 * (find's result limit). The deadline bounds a home-dir walk to
 * WALK_TIMEOUT_MS — partial results are the graceful degradation.
 */
export async function walkFiles(
	root: string,
	visit: (filePath: string) => boolean | Promise<boolean>,
	signal?: AbortSignal,
): Promise<{ timedOut: boolean; aborted: boolean }> {
	const deadline = Date.now() + WALK_TIMEOUT_MS;
	let timedOut = false;
	let aborted = false;
	if (signal?.aborted) return { timedOut: false, aborted: true };

	const walkDir = async (dir: string): Promise<boolean> => {
		if (Date.now() > deadline) {
			timedOut = true;
			return true; // stop
		}
		if (signal?.aborted) {
			aborted = true;
			return true; // stop — abort yields partial results, not a throw
		}
		let entries: import("node:fs").Dirent[];
		try {
			entries = await fs.readdir(dir, { withFileTypes: true });
		} catch {
			return false; // unreadable dir (permissions): skip, keep walking
		}
		for (const entry of entries) {
			if (Date.now() > deadline) {
				timedOut = true;
				return true;
			}
			if (signal?.aborted) {
				aborted = true;
				return true;
			}
			const full = path.join(dir, entry.name);
			if (entry.isDirectory()) {
				if (EXCLUDED_DIR_NAMES.has(entry.name)) continue;
				// The readable scope applies to descendants too: gating only the
				// walk's ROOT would let `grep ~ "sk-ant"` read the key map and
				// emit matching lines. Symlinks are never followed here
				// (isDirectory() is false for them), so the walk cannot leave
				// the root and needs no containment re-check.
				if (isSecretStore(full)) continue;
				if (await walkDir(full)) return true;
			} else if (entry.isFile()) {
				if (isSecretStore(full)) continue;
				if (await visit(full)) return true;
			}
			// symlinks/other: not followed (pi's fd doesn't follow either)
		}
		return false;
	};

	await walkDir(root);
	return { timedOut, aborted };
}

/** True if the first 8KB chunk contains a NUL byte — pi/rg's binary skip. */
export async function isBinaryFile(filePath: string): Promise<boolean> {
	const handle = await fs.open(filePath, "r");
	try {
		const buf = Buffer.alloc(8192);
		const { bytesRead } = await handle.read(buf, 0, 8192, 0);
		return buf.subarray(0, bytesRead).includes(0);
	} finally {
		await handle.close();
	}
}

/** pi's GREP_MAX_LINE_LENGTH line truncation (no mid-word care, hard cap). */
export function truncateGrepLine(line: string): { text: string; wasTruncated: boolean } {
	if (line.length <= GREP_MAX_LINE_LENGTH) return { text: line, wasTruncated: false };
	return { text: `${line.slice(0, GREP_MAX_LINE_LENGTH)}… [truncated]`, wasTruncated: true };
}
