/**
 * The readable scope for the learner-filesystem tools (fs-shared.ts).
 *
 * The fs tools auto-execute, with no approval step, on a context that holds
 * untrusted material (fetched pages, learner PDFs). An unrestricted reader
 * therefore made a prompt-injected turn a credential reader, so every path
 * now passes containment + secret-store rules. These cases are the guard:
 * if they fail, `read`/`ls`/`find`/`grep`/the pdf job can reach the BYOK key
 * map, the provider OAuth stores, or the learner's SSH keys again.
 */
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, it } from "node:test";
import { resolveSourcePath } from "../src/agent/tools/fs-shared.ts";
import { readTool } from "../src/agent/tools/read.ts";
import { grepTool } from "../src/agent/tools/grep.ts";
import { findTool } from "../src/agent/tools/find.ts";

const OUT_OF_SCOPE = /outside the readable scope/;
const original = process.env.LH_FS_ROOTS;

/** Fixtures live under home so containment passes and only the
 *  secret-store rule is under test. Cleaned up per case. */
async function inHome(name: string): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.homedir(), `lh-scope-${name}-`));
	return dir;
}

afterEach(() => {
	if (original === undefined) delete process.env.LH_FS_ROOTS;
	else process.env.LH_FS_ROOTS = original;
});

describe("readable scope — containment", () => {
	it("allows the learner's home itself and paths under it", async () => {
		assert.equal(await resolveSourcePath(), path.resolve(os.homedir()));
		const dir = await inHome("ok");
		try {
			const file = path.join(dir, "notes.md");
			await fs.writeFile(file, "derivatives", "utf-8");
			assert.equal(await resolveSourcePath(file), file);
			// Relative paths keep anchoring at home (sources v1 behavior).
			assert.equal(
				await resolveSourcePath(path.relative(os.homedir(), file)),
				file,
			);
		} finally {
			await fs.rm(dir, { recursive: true, force: true });
		}
	});

	it("refuses an absolute path outside every root", async () => {
		const outside = process.platform === "win32" ? "C:\\Windows\\win.ini" : "/etc/passwd";
		await assert.rejects(() => resolveSourcePath(outside), OUT_OF_SCOPE);
	});

	it("refuses traversal that climbs out of home", async () => {
		await assert.rejects(
			() => resolveSourcePath(path.join("..", "..", "..", "etc", "passwd")),
			OUT_OF_SCOPE,
		);
	});

	it("admits a root whose declared spelling differs from its real path", async () => {
		// The two spellings of one directory routinely differ: macOS resolves
		// /var/folders to /private/var/folders, Windows hands out 8.3 short
		// names. Comparing a resolved target against an unresolved root locked
		// the learner out of their own files; a symlinked root reproduces it.
		const real = await fs.mkdtemp(path.join(os.homedir(), "lh-scope-real-"));
		const link = path.join(os.homedir(), `lh-scope-link-${process.pid}`);
		try {
			try {
				await fs.symlink(real, link, "dir");
			} catch {
				return; // Windows without developer mode: no symlink privilege.
			}
			const file = path.join(real, "notes.md");
			await fs.writeFile(file, "topology", "utf-8");
			process.env.LH_FS_ROOTS = link; // declared via the link
			assert.equal(await resolveSourcePath(file), file, "real path under a linked root");
			assert.equal(await resolveSourcePath(path.join(link, "notes.md")), path.join(link, "notes.md"));
		} finally {
			await fs.rm(link, { recursive: true, force: true });
			await fs.rm(real, { recursive: true, force: true });
		}
	});

	it("admits an extra root only when LH_FS_ROOTS names it", async () => {
		const external = await fs.mkdtemp(path.join(os.tmpdir(), "lh-scope-ext-"));
		const file = path.join(external, "notes.md");
		await fs.writeFile(file, "eigenvectors", "utf-8");
		try {
			// tmpdir is inside home on Windows, so only assert the refusal where
			// it genuinely sits outside.
			if (!path.resolve(os.tmpdir()).startsWith(path.resolve(os.homedir()))) {
				delete process.env.LH_FS_ROOTS;
				await assert.rejects(() => resolveSourcePath(file), OUT_OF_SCOPE);
			}
			process.env.LH_FS_ROOTS = external;
			assert.equal(await resolveSourcePath(file), file);
		} finally {
			await fs.rm(external, { recursive: true, force: true });
		}
	});
});

describe("readable scope — secret stores", () => {
	// The files an injected turn actually wants. Each is refused even though
	// it sits inside an allowed root.
	for (const name of [
		"auth.json",
		"anthropic-credentials.json",
		"chatgpt-credentials.json",
		"github-copilot-credentials.json",
		".env",
		".env.local",
		".netrc",
		".npmrc",
		".git-credentials",
	]) {
		it(`refuses ${name} inside an allowed root`, async () => {
			const dir = await inHome("secret");
			try {
				const file = path.join(dir, name);
				await fs.writeFile(file, "KEY=sk-ant-secret", "utf-8");
				await assert.rejects(() => resolveSourcePath(file), OUT_OF_SCOPE);
			} finally {
				await fs.rm(dir, { recursive: true, force: true });
			}
		});
	}

	for (const dirName of [".ssh", ".aws", ".gnupg", ".kube"]) {
		it(`refuses anything under ${dirName}`, async () => {
			const dir = await inHome("keydir");
			try {
				await fs.mkdir(path.join(dir, dirName), { recursive: true });
				const file = path.join(dir, dirName, "id_rsa");
				await fs.writeFile(file, "-----BEGIN PRIVATE KEY-----", "utf-8");
				await assert.rejects(() => resolveSourcePath(file), OUT_OF_SCOPE);
				// The directory itself is refused too, so ls cannot enumerate it.
				await assert.rejects(() => resolveSourcePath(path.join(dir, dirName)), OUT_OF_SCOPE);
			} finally {
				await fs.rm(dir, { recursive: true, force: true });
			}
		});
	}

	it("matches secret names case-insensitively", async () => {
		const dir = await inHome("case");
		try {
			const file = path.join(dir, "AUTH.JSON");
			await fs.writeFile(file, "{}", "utf-8");
			await assert.rejects(() => resolveSourcePath(file), OUT_OF_SCOPE);
		} finally {
			await fs.rm(dir, { recursive: true, force: true });
		}
	});

	it("still allows ordinary study files with similar names", async () => {
		const dir = await inHome("similar");
		try {
			for (const name of ["environment.md", "credentials-essay.md", "authentication.json"]) {
				const file = path.join(dir, name);
				await fs.writeFile(file, "study material", "utf-8");
				assert.equal(await resolveSourcePath(file), file, name);
			}
		} finally {
			await fs.rm(dir, { recursive: true, force: true });
		}
	});
});

describe("readable scope — recursive tools", () => {
	// Gating only the walk's root would leave the real attack open: point
	// grep at an allowed directory and let it read the secrets underneath.
	async function tree(): Promise<string> {
		const dir = await inHome("walk");
		await fs.writeFile(path.join(dir, "notes.md"), "sk-ant-decoy in study notes", "utf-8");
		await fs.writeFile(path.join(dir, "auth.json"), '{"ANTHROPIC_API_KEY":"sk-ant-leaked"}', "utf-8");
		await fs.writeFile(path.join(dir, ".env.local"), "OPENROUTER_API_KEY=sk-or-leaked", "utf-8");
		await fs.mkdir(path.join(dir, ".ssh"), { recursive: true });
		await fs.writeFile(path.join(dir, ".ssh", "id_rsa"), "sk-ant-not-really-but-matches", "utf-8");
		return dir;
	}

	const textOf = async (tool: { execute?: unknown }, params: unknown) => {
		const result = await (tool as { execute: (id: string, p: unknown) => Promise<{ content: { type: string; text?: string }[] }> }).execute("c", params);
		return result.content.map((part) => (part.type === "text" ? part.text ?? "" : "")).join("\n");
	};

	it("grep never reads a secret store under an allowed root", async () => {
		const dir = await tree();
		try {
			const out = await textOf(grepTool, { path: dir, pattern: "sk-" });
			assert.match(out, /notes\.md/, "ordinary files are still searched");
			for (const leaked of ["sk-ant-leaked", "sk-or-leaked", "id_rsa", "auth.json", ".env.local"]) {
				assert.ok(!out.includes(leaked), `grep output must not carry ${leaked}`);
			}
		} finally {
			await fs.rm(dir, { recursive: true, force: true });
		}
	});

	it("find never lists a secret store under an allowed root", async () => {
		const dir = await tree();
		try {
			const out = await textOf(findTool, { path: dir, pattern: "**/*" });
			assert.match(out, /notes\.md/);
			for (const hidden of ["auth.json", ".env.local", "id_rsa"]) {
				assert.ok(!out.includes(hidden), `find output must not list ${hidden}`);
			}
		} finally {
			await fs.rm(dir, { recursive: true, force: true });
		}
	});
});

describe("readable scope — symlinks and disclosure", () => {
	it("refuses a symlink inside a root that aims at a secret store", async () => {
		const dir = await inHome("link");
		try {
			const secret = path.join(dir, "auth.json");
			await fs.writeFile(secret, "KEY=sk-ant-secret", "utf-8");
			const link = path.join(dir, "harmless-notes.md");
			try {
				await fs.symlink(secret, link);
			} catch {
				return; // Windows without developer mode: no symlink privilege.
			}
			// Lexically innocent, so only symlink resolution catches this one.
			await assert.rejects(() => resolveSourcePath(link), OUT_OF_SCOPE);
		} finally {
			await fs.rm(dir, { recursive: true, force: true });
		}
	});

	it("gives a denied path and a missing path the same refusal, leaking no existence", async () => {
		const dir = await inHome("oracle");
		try {
			const real = path.join(dir, "auth.json");
			await fs.writeFile(real, "KEY=sk-ant-secret", "utf-8");
			const absent = path.join(dir, "nested", "deeper", "auth.json");
			const messages = await Promise.all(
				[real, absent].map((p) => resolveSourcePath(p).then(() => "resolved", (e: Error) => e.message)),
			);
			assert.match(messages[0]!, OUT_OF_SCOPE);
			assert.equal(messages[0], messages[1], "an existing secret and an absent one read alike");
		} finally {
			await fs.rm(dir, { recursive: true, force: true });
		}
	});

	it("surfaces the refusal through the read tool, not just the resolver", async () => {
		const dir = await inHome("tool");
		try {
			const file = path.join(dir, "auth.json");
			await fs.writeFile(file, "KEY=sk-ant-secret", "utf-8");
			// read's contract (read.ts): an unreadable path throws, and pi's
			// runner turns that into the error tool result the model recovers
			// from. What matters here is that the body never comes back.
			await assert.rejects(
				() => readTool.execute!("c", { path: file }),
				(error: Error) => {
					assert.match(error.message, OUT_OF_SCOPE);
					assert.ok(!error.message.includes("sk-ant-secret"), "no body in the refusal");
					return true;
				},
			);
		} finally {
			await fs.rm(dir, { recursive: true, force: true });
		}
	});
});
