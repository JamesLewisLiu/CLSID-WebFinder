'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const scanner = require('./scanner');

function element() {
  const listeners = {};
  return {
    classList: { add() {}, remove() {}, toggle() {} },
    children: [], textContent: '', hidden: false,
    addEventListener(name, fn) { listeners[name] = fn; },
    replaceChildren(...items) { this.children = items; },
    append(...items) { this.children.push(...items); },
    click() {},
    listeners
  };
}

const ids = ['candidate-list', 'candidate-count', 'clue-list', 'clue-count', 'clue-details', 'result-kind', 'results', 'status', 'file-name', 'primary-clsid', 'primary-explanation', 'copy-button', 'export-button', 'copy-state', 'pe-format', 'pe-arch', 'pe-size', 'pe-sha', 'pe-exports', 'file-input', 'dropzone'];
const nodes = Object.fromEntries(ids.map(id => [id, element()]));
const context = {
  ClvsdScanner: scanner,
  document: { getElementById: id => nodes[id], createElement: element },
  window: { addEventListener() {}, getSelection() {} },
  navigator: {}, URL: {}, Blob: function () {}, setTimeout,
  requestAnimationFrame: callback => callback(),
  crypto: require('node:crypto').webcrypto,
  console
};
context.globalThis = context;
vm.runInNewContext(fs.readFileSync('app.js', 'utf8'), context);

async function main() {
  let reads = 0;
  const file = { name: 'oversized.ax', size: scanner.MAX_SIZE + 1, arrayBuffer() { reads++; throw new Error('must not read'); } };
  const target = { files: [file], value: 'selected' };
  nodes['file-input'].listeners.change({ target });
  assert.equal(reads, 0, 'oversized file contents must not be read');
  assert.match(nodes.status.textContent, /exceeds 4 MiB/);
  assert.equal(target.value, '', 'input is reset so the same file can be reselected');
  assert.equal(nodes['export-button'].hidden, true);
  console.log('PASS oversized file is rejected before arrayBuffer()');

  let finishOldRead;
  const older = context.analyze({ name: 'older.ax', size: 0, arrayBuffer: () => new Promise(resolve => { finishOldRead = resolve; }) });
  await context.analyze({ name: 'newer.ax', size: scanner.MAX_SIZE + 1, arrayBuffer() { throw new Error('must not read'); } });
  finishOldRead(new ArrayBuffer(0));
  await older;
  assert.equal(nodes['file-name'].textContent, 'newer.ax');
  assert.match(nodes.status.textContent, /exceeds 4 MiB/);
  assert.equal(nodes['primary-clsid'].textContent, 'Unable to parse');
  console.log('PASS an older file read cannot overwrite the latest selection');

  const parsePE = scanner.parsePE;
  scanner.parsePE = () => ({
    format: 'PE32', machine: 0x14C, size: 32, imageBase: '0x1C400000', sections: [], exports: [{ name: 'DllGetClassObject', forwarded: false }],
    rows: [], warnings: ['Most PE section names are missing; a packed or protected factory layout may not be statically readable.'],
    clues: [{ value: scanner.KNOWN[1].value, label: 'PDVD8 CLVSD decoder', offset: 12, kind: 'binary' }],
    primary: null, knownDecoderClue: { value: scanner.KNOWN[1].value, label: 'PDVD8 CLVSD decoder', offset: 12, kind: 'binary' }
  });
  await context.analyze({ name: 'protected.ax123', size: 32, arrayBuffer: async () => new ArrayBuffer(32) });
  scanner.parsePE = parsePE;
  assert.equal(nodes['primary-clsid'].textContent, scanner.KNOWN[1].value);
  assert.match(nodes['result-kind'].textContent, /factory unverified/);
  assert.match(nodes['primary-explanation'].textContent, /does not prove this DLL provides the class/);
  assert.equal(nodes['copy-button'].textContent, 'Copy GUID clue');
  assert.equal(nodes['clue-details'].open, true);
  console.log('PASS a known binary GUID is shown as an unverified clue, not a factory match');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
