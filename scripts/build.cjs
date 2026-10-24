'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_site');
fs.mkdirSync(out, { recursive: true });
// Publish only these files, never test fixtures or local AX samples.
for (const file of ['index.html', 'scanner.js', 'app.js']) {
  fs.copyFileSync(path.join(root, file), path.join(out, file));
}
fs.writeFileSync(path.join(out, '.nojekyll'), '');
console.log('Static site built in _site/');
