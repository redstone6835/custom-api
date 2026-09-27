package gateway

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// The front end is served from disk rather than embedded.
//
// Why not go:embed: the built single-page app is produced by npm into a
// directory that does not exist in a clean checkout. Embedding it would make
// `go build` fail until someone runs the front-end build, which is a bad trade
// for a project whose deployment story is "one self-contained binary": the
// binary must build from source with nothing but a Go toolchain.
//
// The assets are therefore located at runtime, and when they are absent the
// gateway serves a self-describing placeholder. That keeps three things true at
// once: a clean checkout builds, a deployment needs no separate web server, and
// a missing front-end build is obvious rather than mysterious.

// WebDirEnv overrides the directory the front end is served from.
const WebDirEnv = "CUSTOMS_WEB_DIR"

// defaultWebDirs are searched in order for a built index.html. The list covers
// running from the source tree, from a release directory, and from the
// installed location on FreeBSD.
var defaultWebDirs = []string{
	"web/dist",
	"web",
	"../web/dist",
	"../../web/dist",
	"/usr/local/share/customapi/web/dist",
	"/usr/local/share/customapi/web",
}

// spaHandler serves the single-page app, or a placeholder explaining how to
// build it.
func (s *Server) spaHandler() http.Handler {
	dir := s.locateWebDir()
	if dir == "" {
		return http.HandlerFunc(serveWebPlaceholder)
	}
	fileServer := http.FileServer(http.Dir(dir))
	root := os.DirFS(dir)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			serveIndexOrPlaceholder(w, dir)
			return
		}
		if _, err := fs.Stat(root, path); err != nil {
			// Not a file: treat it as an application route and hand back the
			// shell so a refresh on a deep link works.
			serveIndexOrPlaceholder(w, dir)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// locateWebDir finds a directory holding a built index.html.
func (s *Server) locateWebDir() string {
	if override := os.Getenv(WebDirEnv); override != "" {
		if fileExists(filepath.Join(override, "index.html")) {
			return override
		}
	}
	for _, dir := range defaultWebDirs {
		candidate := dir
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(s.base, dir)
		}
		if fileExists(filepath.Join(candidate, "index.html")) {
			return candidate
		}
	}
	return ""
}

// serveIndexOrPlaceholder returns index.html, falling back to the placeholder
// if it has disappeared since the directory was located.
func serveIndexOrPlaceholder(w http.ResponseWriter, dir string) {
	b, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		serveWebPlaceholder(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The shell must not be cached: it references hashed asset names that change
	// on every build, and a stale shell 404s its own assets.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}

// serveWebPlaceholder explains that the UI has not been built.
//
// It deliberately documents the admin API, because the API is fully usable
// without the UI and an operator who lands here should not be blocked.
func serveWebPlaceholder(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(placeholderHTML))
}

// fileExists reports whether a path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

const placeholderHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Custom-API 海关网关</title>
<style>
  body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0f1115;color:#e6e6e6;
       margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{max-width:680px;padding:2.5rem;background:#171a21;border:1px solid #2a2f3a;border-radius:12px}
  h1{margin:0 0 .75rem;font-size:1.35rem}
  p{line-height:1.75;color:#a8b0bd;margin:.6rem 0}
  code{background:#0f1115;padding:.15rem .4rem;border-radius:4px;color:#7dd3fc;font-size:.9em}
  ul{line-height:1.9;color:#a8b0bd}
  .ok{color:#4ade80}.warn{color:#fbbf24}
</style>
</head>
<body>
<div class="card">
  <h1>Custom-API 海关网关</h1>
  <p class="ok">网关正在运行，管理 API 完全可用。</p>
  <p class="warn">前端界面尚未构建，因此这里显示的是占位页。</p>
  <p>构建前端：<code>cd src/customapi/web &amp;&amp; npm ci &amp;&amp; npm run build</code></p>
  <p>或把已构建的目录指给网关：<code>CUSTOMS_WEB_DIR=/path/to/dist</code></p>
  <p>在构建之前，可以直接使用这些接口：</p>
  <ul>
    <li><code>GET /admin/stats</code> — 运行状态与计数</li>
    <li><code>GET /admin/providers</code> — 提供商、密钥与健康度</li>
    <li><code>GET /admin/models</code> — 模型目录（发现 + 手写）</li>
    <li><code>POST /admin/models/refresh</code> — 立即重新发现模型</li>
    <li><code>GET /admin/usage</code> — 按渠道/模型/用户聚合</li>
    <li><code>GET /admin/audit</code> — 审计记录</li>
    <li><code>GET /admin/audit/verify</code> — 校验哈希链完整性</li>
    <li><code>GET /v1/models</code> — 用户可见的模型列表（需 API Key）</li>
  </ul>
</div>
</body>
</html>`
