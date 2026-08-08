// 构建 Web 只读端并输出到 server/internal/web/dist（产物提交进仓库，服务器无需 Node）
import esbuild from "esbuild";
import { copyFileSync, mkdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const root = dirname(fileURLToPath(import.meta.url));
const outdir = join(root, "..", "server", "internal", "web", "dist");
mkdirSync(outdir, { recursive: true });

await esbuild.build({
	entryPoints: [join(root, "src", "app.ts"), join(root, "src", "share.ts")],
	bundle: true,
	minify: true,
	format: "iife",
	target: "es2020",
	outdir,
	logLevel: "info",
});

for (const f of ["index.html", "share.html", "styles.css"]) {
	copyFileSync(join(root, f), join(outdir, f));
}
console.log("web dist ->", outdir);
