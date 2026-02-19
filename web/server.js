import http from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';

const HOST = '0.0.0.0';
const PORT = Number(process.env.PORT || 8080);
const DIST_DIR = join(process.cwd(), 'dist');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.xml': 'application/xml; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

function safePath(pathname) {
  const decoded = decodeURIComponent(pathname.split('?')[0] || '/');
  const cleaned = normalize(decoded).replace(/^(\.\.(\/|\\|$))+/, '');
  return cleaned.startsWith('/') ? cleaned : `/${cleaned}`;
}

function serveFile(res, filePath) {
  try {
    const stat = statSync(filePath);
    if (!stat.isFile()) return false;
    const type = MIME[extname(filePath).toLowerCase()] || 'application/octet-stream';
    res.statusCode = 200;
    res.setHeader('content-type', type);
    createReadStream(filePath).pipe(res);
    return true;
  } catch (_error) {
    return false;
  }
}

function resolveStatic(pathname) {
  const full = join(DIST_DIR, pathname);
  if (existsSync(full)) {
    try {
      const stat = statSync(full);
      if (stat.isDirectory()) {
        const indexFile = join(full, 'index.html');
        if (existsSync(indexFile)) return indexFile;
      } else if (stat.isFile()) {
        return full;
      }
    } catch (_error) {}
  }

  const htmlCandidate = join(DIST_DIR, `${pathname}.html`);
  if (existsSync(htmlCandidate)) return htmlCandidate;
  return '';
}

const server = http.createServer((req, res) => {
  const pathname = safePath(req.url || '/');

  if (pathname === '/docs' || pathname === '/docs/') {
    res.statusCode = 302;
    res.setHeader('location', '/doc/');
    res.end();
    return;
  }
  if (pathname.startsWith('/docs/')) {
    const suffix = pathname.slice('/docs/'.length);
    res.statusCode = 302;
    res.setHeader('location', `/doc/docs/${suffix}`);
    res.end();
    return;
  }

  if (pathname.startsWith('/doc')) {
    const docFile = resolveStatic(pathname);
    if (docFile && serveFile(res, docFile)) return;
    const docIndex = join(DIST_DIR, 'doc', 'index.html');
    if (serveFile(res, docIndex)) return;
    res.statusCode = 404;
    res.end('Not Found');
    return;
  }

  const staticFile = resolveStatic(pathname);
  if (staticFile && serveFile(res, staticFile)) return;

  const appIndex = join(DIST_DIR, 'index.html');
  if (serveFile(res, appIndex)) return;

  res.statusCode = 404;
  res.end('Not Found');
});

server.listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.log(`bluearc web listening on ${HOST}:${PORT}`);
});
