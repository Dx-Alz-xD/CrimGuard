'use strict';

// Builds a static copy of Red into demo/: the real pages, styles and client script, with
// scripts/demo/demo-api.js standing in for the server. Open demo/index.html directly, or publish
// the folder on any static host such as GitHub Pages. Rebuild after changing anything in public/.

const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..', '..');
const publicDir = path.join(root, 'public');
const outDir = path.join(root, 'demo');

// Longest paths first, so "/admin/login" is never rewritten as "/admin".
const PAGE_LINKS = [
  ['/admin/login', 'admin-login.html'],
  ['/dashboard', 'dashboard.html'],
  ['/signup', 'signup.html'],
  ['/login', 'login.html'],
  ['/admin', 'admin.html'],
  ['/', 'index.html'],
];

function toStatic(html) {
  let out = html.replaceAll('"/static/', '"static/');
  for (const [from, to] of PAGE_LINKS) out = out.replaceAll(`href="${from}"`, `href="${to}"`);

  const demoScript = '<script src="static/demo-api.js"></script>';
  out = out.includes('<script src="static/app.js"></script>')
    ? out.replace('<script src="static/app.js"></script>', `${demoScript}\n  <script src="static/app.js"></script>`)
    : out.replace('</body>', `  ${demoScript}\n</body>`);

  const leftover = out.match(/(?:href|src)="\/(?!\/)[^"]*"/);
  if (leftover) throw new Error(`Unmapped absolute path in demo page: ${leftover[0]}`);
  return out;
}

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });
fs.cpSync(path.join(publicDir, 'static'), path.join(outDir, 'static'), { recursive: true });
fs.copyFileSync(path.join(__dirname, 'demo-api.js'), path.join(outDir, 'static', 'demo-api.js'));

const pages = fs.readdirSync(publicDir).filter((file) => file.endsWith('.html'));
for (const file of pages) {
  fs.writeFileSync(path.join(outDir, file), toStatic(fs.readFileSync(path.join(publicDir, file), 'utf8')));
}

console.log(`Built the static demo: ${pages.length} pages in ${path.relative(process.cwd(), outDir) || '.'}`);
console.log('Open demo/index.html in a browser. Demo sign-ins are shown on both login pages.');
