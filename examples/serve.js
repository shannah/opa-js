/**
 * Tiny dev server for the browser-rss example.
 * Serves static files and proxies RSS feed requests to avoid CORS issues.
 *
 * Usage: node examples/serve.js
 *        Then open http://localhost:3000/examples/browser-rss.html
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = 3000;
const ROOT = join(fileURLToPath(import.meta.url), '..', '..');

const MIME = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.json': 'application/json',
  '.css':  'text/css',
  '.md':   'text/markdown',
};

createServer(async (req, res) => {
  // Proxy endpoint: /proxy?url=<encoded-url>
  if (req.url.startsWith('/proxy?url=')) {
    const target = decodeURIComponent(req.url.slice('/proxy?url='.length));
    try {
      const upstream = await fetch(target);
      const body = await upstream.text();
      res.writeHead(200, {
        'Content-Type': upstream.headers.get('content-type') || 'text/xml',
        'Access-Control-Allow-Origin': '*',
      });
      res.end(body);
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end(`Proxy error: ${err.message}`);
    }
    return;
  }

  // Static file server
  const urlPath = req.url === '/' ? '/examples/browser-rss.html' : req.url.split('?')[0];
  const filePath = join(ROOT, urlPath);

  try {
    const data = await readFile(filePath);
    const ext = extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  }
}).listen(PORT, () => {
  console.log(`Serving at http://localhost:${PORT}`);
  console.log(`Open http://localhost:${PORT}/examples/browser-rss.html`);
});
