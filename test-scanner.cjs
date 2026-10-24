'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const scanner = require('./scanner');

// Purpose-built PE fixture uses distinct RVAs/raw offsets and an unknown CLSID.
function fixture(is64 = false) {
  const b = Buffer.alloc(0xA00), pe = 0x80, opt = pe + 24, optSize = is64 ? 240 : 224;
  b.write('MZ'); b.writeUInt32LE(pe, 0x3C); b.write('PE\0\0', pe, 'binary');
  b.writeUInt16LE(is64 ? 0x8664 : 0x14C, pe + 4); b.writeUInt16LE(2, pe + 6); b.writeUInt16LE(optSize, pe + 20);
  b.writeUInt16LE(is64 ? 0x20B : 0x10B, opt);
  const imageBase = is64 ? 0x20000000000000n : 0x10000000n;
  if (is64) b.writeBigUInt64LE(imageBase, opt + 24); else b.writeUInt32LE(Number(imageBase), opt + 28);
  b.writeUInt32LE(0x200, opt + 60); b.writeUInt32LE(16, opt + (is64 ? 108 : 92));
  b.writeUInt32LE(0x2000, opt + (is64 ? 112 : 96)); b.writeUInt32LE(0x80, opt + (is64 ? 116 : 100));
  for (const [i, name, rva, raw, size, flags] of [[0, '.text', 0x1000, 0x200, 0x200, 0x60000020], [1, '.rdata', 0x2000, 0x400, 0x600, 0x40000040]]) {
    const o = opt + optSize + i * 40; b.write(name, o);
    for (const [delta, val] of [[8,size],[12,rva],[16,size],[20,raw],[36,flags]]) b.writeUInt32LE(val, o + delta);
  }
  for (const [o, val] of [[0x414,1],[0x418,1],[0x41C,0x2040],[0x420,0x2048],[0x424,0x2050],[0x440,0x1010],[0x448,0x2060]]) b.writeUInt32LE(val, o);
  b.write('DllGetClassObject\0', 0x460);
  const width = is64 ? 8 : 4;
  const pointer = (o, rva) => is64 ? b.writeBigUInt64LE(imageBase + BigInt(rva), o) : b.writeUInt32LE(Number(imageBase) + rva, o);
  pointer(0x500, 0x2180); pointer(0x500 + width, 0x2200); pointer(0x500 + 2 * width, 0x1010);
  pointer(0x500 + 4 * width, 0x2220); pointer(0x620, 0x2200); pointer(0x620 + width, 0x2180);
  b.write('Test Custom Decoder\0', 0x580, 'utf16le');
  const value = '{12345678-1234-5678-9ABC-DEF012345678}';
  Buffer.from(scanner.guidBytes(value)).copy(b, 0x600);
  return { b, value };
}
let checks = 0;
function check(name, fn) { fn(); checks++; console.log('PASS', name); }
for (const is64 of [false, true]) {
  check(`unknown CLSID / pointer mapping / ${is64 ? 'PE32+' : 'PE32'}`, () => {
    const { b, value } = fixture(is64), result = scanner.parsePE(b);
    assert.equal(result.primary.value, value);
    assert.equal(result.primary.offset, 0x600); assert.equal(result.primary.tableRva, 0x2100);
    assert.equal(result.primary.createRva, 0x1010); assert.equal(result.rows.length, 1);
    assert.equal(result.format, is64 ? 'PE32+' : 'PE32');
  });
}
check('a known GUID alone is not a decoder result', () => {
  const { b } = fixture(); b.fill(0, 0x500, 0x514);
  Buffer.from(scanner.guidBytes(scanner.KNOWN[0].value)).copy(b, 0x800);
  const r = scanner.parsePE(b); assert.equal(r.primary, null); assert.equal(r.rows.length, 0);
  assert.equal(r.clues.find(c => c.kind === 'binary').offset, 0x800);
  assert.equal(r.knownDecoderClue.value, scanner.KNOWN[0].value);
});
check('protected layout retains a known GUID clue without claiming a factory', () => {
  const { b } = fixture(); b.fill(0, 0x500, 0x514);
  const sectionTable = 0x80 + 24 + 224;
  b.fill(0, sectionTable, sectionTable + 8); b.fill(0, sectionTable + 40, sectionTable + 48);
  Buffer.from(scanner.guidBytes(scanner.KNOWN[1].value)).copy(b, 0x800);
  Buffer.from(scanner.guidBytes(scanner.KNOWN[1].value)).copy(b, 0x820);
  const r = scanner.parsePE(b);
  assert.equal(r.primary, null); assert.equal(r.rows.length, 0);
  assert.equal(r.knownDecoderClue.value, scanner.KNOWN[1].value);
  assert.match(r.warnings[0], /packed or protected/);
  Buffer.from(scanner.guidBytes(scanner.KNOWN[0].value)).copy(b, 0x840);
  assert.equal(scanner.parsePE(b).knownDecoderClue, null);
});
check('text GUIDs or files without a factory export do not get a known-decoder fallback', () => {
  const { b } = fixture(); b.fill(0, 0x500, 0x514);
  b.write(scanner.KNOWN[1].value, 0x800, 'ascii');
  assert.equal(scanner.parsePE(b).knownDecoderClue, null);
  Buffer.from(scanner.guidBytes(scanner.KNOWN[1].value)).copy(b, 0x880);
  b.write('XllGetClassObject', 0x460);
  assert.equal(scanner.parsePE(b).knownDecoderClue, null);
});
check('ASCII and odd-offset UTF-16 text remain clues', () => {
  const { b } = fixture();
  b.write('11111111-2222-3333-4444-555555555555', 0x800, 'ascii');
  b.write('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', 0x881, 'utf16le');
  const r = scanner.parsePE(b);
  assert.equal(r.clues.find(c => c.label === 'ASCII GUID').offset, 0x800);
  assert.equal(r.clues.find(c => c.label === 'UTF-16LE GUID').offset, 0x881);
});
check('no factory export means no factory conclusion', () => {
  const { b } = fixture(); b.write('XllGetClassObject', 0x460);
  assert.equal(scanner.parsePE(b).rows.length, 0);
});
check('a setup record must agree with the class pointer', () => {
  const { b } = fixture(); b.writeUInt32LE(0x10002210, 0x620);
  assert.equal(scanner.parsePE(b).rows.length, 0);
});
check('bad / truncated / oversized files are rejected', () => {
  assert.throws(() => scanner.parsePE(Buffer.from('not a PE')));
  const { b } = fixture(); assert.throws(() => scanner.parsePE(b.subarray(0, 0x750)));
  assert.throws(() => scanner.parsePE(Buffer.alloc(scanner.MAX_SIZE + 1)), /4 MiB/);
  b.writeUInt32LE(0xFFFFFFF0, 0x3C); assert.throws(() => scanner.parsePE(b));
});
check('exactly 4 MiB is accepted; one extra byte is rejected', () => {
  const { b, value } = fixture();
  const exact = Buffer.alloc(4 * 1024 * 1024); b.copy(exact);
  assert.equal(scanner.MAX_SIZE, exact.length);
  assert.equal(scanner.parsePE(exact).primary.value, value);
  assert.throws(() => scanner.parsePE(Buffer.alloc(exact.length + 1)), /4 MiB/);
});
const samples = [
  { v: 4, hash: 'c7ba1dff716a4c6cf0ec3cfcb5900c3206eb6ec042e858baebd11f159c06eea2', clsid: scanner.KNOWN[0].value, property: '{D35CD90E-88E2-46A2-9B58-61F4C0520030}' },
  { v: 7, hash: 'a166092b159f991764ccd4bef9eaed2b016cfd71a8a89c74818ba54c60650caf', clsid: scanner.KNOWN[1].value, property: '{5593CF36-190B-4A47-A4DD-9680093DBA1D}' }
];
for (const sample of samples) {
  const file = process.env[`CLVSD_V${sample.v}_AX`];
  if (!file) { console.log('SKIP optional local AX sample', sample.v, '(set CLVSD_V' + sample.v + '_AX)'); continue; }
  check(`real AX v${sample.v} identity, decoder and property class`, () => {
    const b = fs.readFileSync(file); assert.equal(crypto.createHash('sha256').update(b).digest('hex'), sample.hash);
    const r = scanner.parsePE(b); assert.equal(r.primary.value, sample.clsid); assert.equal(r.rows.length, 2);
    assert.ok(r.rows.some(row => row.value === sample.property)); assert.deepEqual(r.warnings, []);
  });
}
for (const [key, hash] of [
  ['CLVSD_PROTECTED_AX', '1393dbaa1c1b21d5f383d542cf90ae1ef93d19a525c2cf0ae3b4ab9a0ff20e1e'],
  ['CLVSD_PROTECTED_DLL', 'c540b83a53cea20dd9374b8aff4ee7408da62504f600670b2fb0a79ecfbc52a0']
]) {
  if (!process.env[key]) { console.log('SKIP optional protected sample (set ' + key + ')'); continue; }
  check(key + ' identity and unverified PDVD8 clue', () => {
    const b = fs.readFileSync(process.env[key]); assert.equal(crypto.createHash('sha256').update(b).digest('hex'), hash);
    const r = scanner.parsePE(b);
    assert.equal(r.primary, null); assert.equal(r.rows.length, 0);
    assert.equal(r.knownDecoderClue.value, scanner.KNOWN[1].value);
    assert.equal(r.knownDecoderClue.offset, 0xACD48);
    assert.match(r.warnings.join(' '), /packed or protected/);
  });
}
console.log(`${checks} checks passed`);
