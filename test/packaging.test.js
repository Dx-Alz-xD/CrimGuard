'use strict';

// The production image copies named directories rather than the whole repository, so a new
// dependency on a directory nobody added a COPY line for only shows up once the container is
// running. This walks what src/ actually requires and checks the Dockerfile ships it.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function* jsFiles(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* jsFiles(full);
    else if (entry.name.endsWith('.js')) yield full;
  }
}

// The top-level directories src/ reaches outside itself, e.g. 'crimguard' and 'database'.
function requiredDirectories() {
  const needed = new Set();
  for (const file of jsFiles(path.join(ROOT, 'src'))) {
    const source = fs.readFileSync(file, 'utf8');
    for (const [, spec] of source.matchAll(/require\('(\.[^']+)'\)/g)) {
      const resolved = path.resolve(path.dirname(file), spec);
      const relative = path.relative(ROOT, resolved).split(path.sep)[0];
      if (relative !== 'src' && !relative.startsWith('..')) needed.add(relative);
    }
  }
  return needed;
}

test('the image copies every directory src/ requires', () => {
  const dockerfile = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8');
  const copied = [...dockerfile.matchAll(/^COPY\s+(\S+)\s/gm)].map((match) => match[1].split('/')[0]);

  for (const dir of requiredDirectories()) {
    assert.ok(copied.includes(dir), `Dockerfile has no COPY for ${dir}/, which src/ requires`);
  }
});

test('the risk engine can find the feature catalog it parses', () => {
  // crimguard/risk/catalog.js reads this by path, so it has to be shipped alongside.
  const catalog = path.join(ROOT, 'database', 'crimguard', '05_feature_catalog.sql');
  assert.ok(fs.existsSync(catalog));
  const dockerfile = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8');
  assert.match(dockerfile, /^COPY database\/crimguard /m);
  assert.match(dockerfile, /^COPY crimguard /m);
});
