'use strict';
const $ = id => document.getElementById(id);
const scanner = globalThis.ClvsdScanner;
let generation = 0, currentClsid = '', report = null;
const node = (tag, className, text) => {
  const element = document.createElement(tag);
  element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};
function renderRows(rows) {
  const list = $('candidate-list');
  list.replaceChildren();
  $('candidate-count').textContent = rows.length + ' item(s)';
  if (!rows.length) list.append(node('div', 'empty', 'No class-factory table was identified. Review GUID clues below.'));
  for (const row of rows) {
    const container = node('div', 'candidate');
    const title = node('div', '');
    title.append(node('div', 'candidate-code', row.value), node('div', 'candidate-kind', row.name));
    container.append(title, node('div', 'candidate-kind', `GUID 0x${scanner.hex(row.offset)} · table 0x${scanner.hex(row.tableOffset)}`), node('span', 'badge', 'Factory candidate'));
    list.append(container);
  }
}
function renderClues(clues) {
  const list = $('clue-list');
  list.replaceChildren();
  $('clue-count').textContent = clues.length + ' item(s)';
  if (!clues.length) list.append(node('p', 'note', 'No additional clues.'));
  for (const row of clues) {
    const container = node('div', 'candidate');
    container.append(node('div', 'candidate-code', row.value), node('div', 'candidate-kind', `${row.label} · 0x${scanner.hex(row.offset)}`), node('span', 'badge neutral', 'Presence clue'));
    list.append(container);
  }
}
async function analyze(file) {
  const request = ++generation;
  currentClsid = ''; report = null;
  $('results').classList.add('visible');
  $('status').classList.remove('error');
  $('status').textContent = 'Reading file…';
  $('file-name').textContent = file.name;
  $('primary-clsid').textContent = 'Analyzing…';
  $('result-kind').textContent = 'Primary match';
  $('copy-button').textContent = 'Copy CLSID';
  $('clue-details').open = false;
  $('primary-explanation').textContent = 'Reading PE sections, exports, and DirectShow class-factory templates.';
  $('copy-button').classList.remove('visible');
  $('export-button').hidden = true;
  $('copy-state').textContent = '';
  for (const id of ['pe-format', 'pe-arch', 'pe-size', 'pe-sha', 'pe-exports']) $(id).textContent = '—';
  renderRows([]); renderClues([]);
  try {
    if (file.size > scanner.MAX_SIZE) throw new Error('File exceeds 4 MiB (4,194,304 bytes); contents were not read.');
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (request !== generation) return;
    // Yield a frame so the reading state is painted before synchronous inspection.
    await new Promise(resolve => requestAnimationFrame(resolve));
    if (request !== generation) return;
    const result = scanner.parsePE(bytes);
    let hash = 'SHA-256 is unavailable in this browser';
    if (globalThis.crypto?.subtle) {
      const digest = await crypto.subtle.digest('SHA-256', bytes);
      hash = Array.from(new Uint8Array(digest), v => scanner.hex(v, 2)).join('');
    }
    if (request !== generation) return;
    report = { file: file.name, sha256: hash, ...result };
    $('status').textContent = `Analysis complete · ${result.rows.length} factory candidate(s) · ${result.clues.length} other clue(s)`;
    $('pe-format').textContent = result.format;
    $('pe-arch').textContent = ({ 0x14C: 'x86 / 32-bit', 0x8664: 'x64 / 64-bit', 0xAA64: 'ARM64' })[result.machine] || `Machine 0x${scanner.hex(result.machine, 4)}`;
    $('pe-size').textContent = file.size.toLocaleString('en-US') + ' bytes';
    $('pe-sha').textContent = hash;
    $('pe-exports').textContent = result.exports.map(e => e.name + (e.forwarded ? ' (forwarded)' : '')).join(', ') || 'No named exports';
    const primary = result.primary;
    if (primary) {
      currentClsid = primary.value;
      $('primary-clsid').textContent = primary.value;
      $('primary-explanation').textContent = `${primary.name}. ${primary.label ? primary.label + '. ' : ''}A factory candidate links a class name, GUID pointer, and creation function. File offset 0x${scanner.hex(primary.offset)}. Static identification does not prove runtime activation.`;
      $('copy-button').classList.add('visible');
    } else if (result.knownDecoderClue) {
      const clue = result.knownDecoderClue;
      currentClsid = clue.value;
      $('result-kind').textContent = 'Known decoder GUID clue · factory unverified';
      $('primary-clsid').textContent = clue.value;
      $('primary-explanation').textContent = `${clue.label} GUID bytes found at file offset 0x${scanner.hex(clue.offset)}. No readable class-factory table was found. Packed or protected files can hide that table; the GUID's presence does not prove this DLL provides the class.`;
      $('copy-button').textContent = 'Copy GUID clue';
      $('copy-button').classList.add('visible');
      $('clue-details').open = true;
    } else {
      $('primary-clsid').textContent = result.rows.length ? 'Review matching classes' : 'No decoder identified';
      $('primary-explanation').textContent = result.rows.length ? 'Multiple candidates exist, or none is named Decoder. Review the class names below.' : 'The static rules found no decoder class. Review GUID clues or inspect DllGetClassObject further; a miss does not prove the file lacks the class.';
      $('clue-details').open = result.clues.length > 0;
    }
    if (result.warnings.length) $('primary-explanation').append(node('span', '', ' ' + result.warnings.join('; ')));
    renderRows(result.rows); renderClues(result.clues);
    $('export-button').hidden = false;
  } catch (error) {
    if (request !== generation) return;
    $('status').classList.add('error');
    $('status').textContent = 'Analysis failed · ' + error.message;
    $('primary-clsid').textContent = 'Unable to parse';
    $('primary-explanation').textContent = 'Choose a complete PE32 / PE32+ AX or DLL no larger than 4 MiB. Packed files and non-standard factory layouts may not be recognized.';
  }
}
$('file-input').addEventListener('change', event => {
  const file = event.target.files[0];
  if (file) analyze(file);
  event.target.value = ''; // Allow reselecting the same file.
});
for (const name of ['dragenter', 'dragover', 'dragleave', 'drop']) {
  $('dropzone').addEventListener(name, event => {
    event.preventDefault();
    $('dropzone').classList.toggle('dragging', name === 'dragenter' || name === 'dragover');
    if (name === 'drop' && event.dataTransfer.files[0]) analyze(event.dataTransfer.files[0]);
  });
}
// Avoid browser navigation when a file is accidentally dropped outside the panel.
for (const name of ['dragover', 'drop']) window.addEventListener(name, event => event.preventDefault());
$('copy-button').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(currentClsid); $('copy-state').textContent = 'Copied'; }
  catch {
    const range = document.createRange(); range.selectNodeContents($('primary-clsid'));
    const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
    $('copy-state').textContent = 'Selected; press Ctrl+C to copy';
  }
});
$('export-button').addEventListener('click', () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url;
  link.download = report.file.replace(/[^\w.\-]/g, '_') + '.clsid.json';
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
