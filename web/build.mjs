// 构建 Web 只读端并输出到 internal/web/dist（产物提交进仓库，服务器无需 Node）
import esbuild from "esbuild";
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const root = dirname(fileURLToPath(import.meta.url));
const outdir = join(root, "..", "internal", "web", "dist");
mkdirSync(outdir, { recursive: true });

await esbuild.build({
	entryPoints: [
		join(root, "src", "app.ts"), join(root, "src", "share.ts"), join(root, "src", "pair.ts"), join(root, "src", "join.ts"),
		// 网页编辑器（CodeMirror 6）单独成包：只在进入编辑时按需加载
		join(root, "src", "editor.ts"),
	],
	bundle: true,
	minify: true,
	format: "iife",
	target: "es2020",
	outdir,
	logLevel: "info",
});

// 产物逐字节入库：换行统一为 LF，与 checkout 的换行风格无关（Windows 默认 core.autocrlf=true
// 会把源码模板检出成 CRLF——直接复制的话，同一份源码在不同机器上构建出不同字节）
const lf = (p) => readFileSync(p, "utf8").replace(/\r\n/g, "\n");
for (const f of ["index.html", "share.html", "pair.html", "join.html", "styles.css"]) {
	writeFileSync(join(outdir, f), lf(join(root, f)));
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
const viewerHtml = lf(join(root, "viewer.html")).replace(
	"/*__VIEWER_JS__*/",
	() => viewerJs.outputFiles[0].text.replaceAll("</script", "<\\/script"),
);
const viewerOut = join(root, "..", "viewer");
mkdirSync(viewerOut, { recursive: true });
writeFileSync(join(viewerOut, "litesync-viewer.html"), viewerHtml);
console.log("offline viewer ->", join(viewerOut, "litesync-viewer.html"));
