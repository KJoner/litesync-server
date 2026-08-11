// 构建 Web 只读端并输出到 internal/web/dist（产物提交进仓库，服务器无需 Node）
import esbuild from "esbuild";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const root = dirname(fileURLToPath(import.meta.url));
const outdir = join(root, "..", "internal", "web", "dist");
mkdirSync(outdir, { recursive: true });

await esbuild.build({
	entryPoints: [join(root, "src", "app.ts"), join(root, "src", "share.ts"), join(root, "src", "pair.ts")],
	bundle: true,
	minify: true,
	format: "iife",
	target: "es2020",
	outdir,
	logLevel: "info",
});

for (const f of ["index.html", "share.html", "pair.html", "styles.css"]) {
	copyFileSync(join(root, f), join(outdir, f));
}
console.log("web dist ->", outdir);

// 离线单文件分享查看器（v9.2）：JS 内联进 HTML，输出到仓库 viewer/ 目录。
// 用户从仓库下载一次本地保存——不从（可能被攻陷的）同步服务器获取查看器代码。
const viewerJs = await esbuild.build({
	entryPoints: [join(root, "src", "viewer.ts")],
	bundle: true,
	minify: true,
	format: "iife",
	target: "es2020",
	write: false,
});
const viewerHtml = readFileSync(join(root, "viewer.html"), "utf8").replace(
	"/*__VIEWER_JS__*/",
	() => viewerJs.outputFiles[0].text.replaceAll("</script", "<\\/script"),
);
const viewerOut = join(root, "..", "viewer");
mkdirSync(viewerOut, { recursive: true });
writeFileSync(join(viewerOut, "litesync-viewer.html"), viewerHtml);
console.log("offline viewer ->", join(viewerOut, "litesync-viewer.html"));
