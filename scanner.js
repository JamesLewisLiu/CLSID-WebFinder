/* Offline PE / DirectShow factory-template inspection. No target code executes. */
(function (root) {
  'use strict';
  const MAX_SIZE = 4 * 1024 * 1024;
  const KNOWN = [
    { value: '{8ACD52ED-9C2D-4008-9129-DCE955D86065}', label: 'Legacy CLVSD decoder' },
    { value: '{37991D68-42A3-40E3-8C05-037170E1A42A}', label: 'PDVD8 CLVSD decoder' }
  ];
  const hex = (n, width = 8) => n.toString(16).toUpperCase().padStart(width, '0');
  function guidBytes(value) {
    const raw = value.replace(/[{}-]/g, '');
    const bytes = raw.match(/../g).map(x => parseInt(x, 16));
    return [...bytes.slice(0, 4).reverse(), ...bytes.slice(4, 6).reverse(), ...bytes.slice(6, 8).reverse(), ...bytes.slice(8)];
  }
  function parsePE(input) {
    const b = input instanceof Uint8Array ? input : new Uint8Array(input);
    if (b.length > MAX_SIZE) throw new Error('File exceeds 4 MiB (4,194,304 bytes). Choose a smaller AX/DLL file.');
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
    function range(o, n) {
      if (!Number.isSafeInteger(o) || o < 0 || o + n > b.length) throw new Error('The file is truncated or a PE offset is out of bounds.');
      return o;
    }
    const u16 = o => view.getUint16(range(o, 2), true);
    const u32 = o => view.getUint32(range(o, 4), true);
    const u64 = o => view.getBigUint64(range(o, 8), true);
    const ascii = (o, n) => new TextDecoder('latin1').decode(b.subarray(range(o, n), o + n));
    if (b.length < 64 || ascii(0, 2) !== 'MZ') throw new Error('Invalid PE file: missing MZ header.');
    const pe = u32(0x3C);
    range(pe, 24);
    if (u32(pe) !== 0x4550) throw new Error('Invalid PE file: missing PE signature.');
    const count = u16(pe + 6), optSize = u16(pe + 20), opt = pe + 24;
    range(opt, optSize);
    const magic = u16(opt), is64 = magic === 0x20B;
    if (magic !== 0x10B && !is64) throw new Error('Only PE32 and PE32+ files are supported.');
    const minimum = is64 ? 112 : 96;
    if (optSize < minimum || !count || count > 96) throw new Error('Invalid PE optional header or section count.');
    const imageBase = is64 ? u64(opt + 24) : BigInt(u32(opt + 28));
    const headerSize = u32(opt + 60);
    if (headerSize > b.length) throw new Error('PE headers extend beyond the file.');
    const sections = [];
    range(opt + optSize, count * 40);
    for (let i = 0; i < count; i++) {
      const o = opt + optSize + i * 40;
      const s = { name: ascii(o, 8).replace(/\0.*$/, ''), virtualSize: u32(o + 8), rva: u32(o + 12), size: u32(o + 16), offset: u32(o + 20), flags: u32(o + 36) };
      if (s.size) range(s.offset, s.size);
      sections.push(s);
    }
    function map(rva, length = 1) {
      if (!Number.isSafeInteger(rva) || rva < 0) return null;
      if (rva < headerSize && rva + length <= headerSize) return { offset: rva, section: null };
      const s = sections.find(s => rva >= s.rva && rva + length <= s.rva + s.size);
      if (!s) return null; // Do not read zero-filled virtual tails as file bytes.
      const offset = s.offset + rva - s.rva;
      return offset + length <= b.length ? { offset, section: s } : null;
    }
    function va(value, length = 1) {
      const rva = value - imageBase;
      return rva >= 0n && rva <= 0xFFFFFFFFn ? map(Number(rva), length) : null;
    }
    const ptrSize = is64 ? 8 : 4;
    const ptr = o => is64 ? u64(o) : BigInt(u32(o));
    function cstring(rva) {
      const m = map(rva);
      if (!m) return null;
      const limit = Math.min(b.length, m.section ? m.section.offset + m.section.size : headerSize, m.offset + 512);
      let end = m.offset;
      while (end < limit && b[end]) end++;
      return end < limit ? ascii(m.offset, end - m.offset) : null;
    }
    const exports = [], warnings = [];
    const dirCount = u32(opt + (is64 ? 108 : 92));
    if (dirCount && optSize >= minimum + 8) {
      const expRva = u32(opt + minimum), expSize = u32(opt + minimum + 4);
      if (expRva) {
        try {
          const e = map(expRva, 40);
          if (!e) throw new Error('export directory is out of bounds');
          const n = u32(e.offset + 24), funcs = u32(e.offset + 20);
          if (n > 4096) throw new Error('too many named exports');
          const names = map(u32(e.offset + 32), n * 4);
          const ords = map(u32(e.offset + 36), n * 2);
          if (n && (!names || !ords)) throw new Error('export name table is out of bounds');
          for (let i = 0; i < n; i++) {
            const name = cstring(u32(names.offset + i * 4)), ordinal = u16(ords.offset + i * 2);
            const slot = map(u32(e.offset + 28) + ordinal * 4, 4);
            if (ordinal >= funcs || !slot || !name) throw new Error('invalid export entry');
            const rva = u32(slot.offset);
            exports.push({ name, rva, forwarded: rva >= expRva && rva < expRva + expSize });
          }
        } catch (error) { warnings.push('Export table parsing is incomplete: ' + error.message); }
      }
    }
    function guid(o) {
      range(o, 16);
      const tail = Array.from(b.subarray(o + 8, o + 16), v => hex(v, 2)).join('');
      return `{${hex(u32(o))}-${hex(u16(o + 4), 4)}-${hex(u16(o + 6), 4)}-${tail.slice(0, 4)}-${tail.slice(4)}}`;
    }
    function wideName(value) {
      const m = va(value, 2);
      if (!m || (m.section && (m.section.flags & 0x20000000))) return null;
      const limit = Math.min(b.length, m.section ? m.section.offset + m.section.size : headerSize, m.offset + 512);
      let name = '';
      for (let o = m.offset; o + 2 <= limit; o += 2) {
        const c = u16(o);
        if (!c) return name.length >= 3 ? name : null;
        if (c < 32 || c === 0xFFFF || (c >= 0xD800 && c <= 0xDFFF)) return null;
        name += String.fromCharCode(c);
      }
      return null;
    }
    const executable = value => { const m = va(value); return Boolean(m && m.section && (m.section.flags & 0x20000000)); };
    const rows = [];
    // CFactoryTemplate: name*, CLSID*, create*, init*, AMOVIESETUP_FILTER*.
    // In an unknown binary these structural matches remain candidates.
    if (exports.some(e => e.name === 'DllGetClassObject' && !e.forwarded)) {
      for (const s of sections.filter(s => s.size && !(s.flags & 0x20000000))) {
        for (let o = s.offset; o + 5 * ptrSize <= s.offset + s.size; o += ptrSize) {
          const create = ptr(o + 2 * ptrSize);
          if (!executable(create)) continue;
          const clsid = va(ptr(o + ptrSize), 16);
          if (!clsid || (clsid.section && (clsid.section.flags & 0x20000000))) continue;
          const name = wideName(ptr(o));
          if (!name) continue;
          const init = ptr(o + 3 * ptrSize), setup = ptr(o + 4 * ptrSize);
          if ((init && !executable(init)) || (setup && !va(setup, ptrSize))) continue;
          if (setup) {
            const setupMap = va(setup, ptrSize * 2);
            if (!setupMap || ptr(setupMap.offset) !== ptr(o + ptrSize) || !wideName(ptr(setupMap.offset + ptrSize))) continue;
          }
          const value = guid(clsid.offset);
          if (value === '{00000000-0000-0000-0000-000000000000}') continue;
          rows.push({ value, name, offset: clsid.offset, tableOffset: o, tableRva: s.rva + o - s.offset, createRva: Number(create - imageBase), hasSetup: Boolean(setup), kind: 'factory', label: KNOWN.find(k => k.value === value)?.label || '' });
        }
      }
    }
    const clues = [];
    for (const k of KNOWN) {
      const pattern = guidBytes(k.value);
      for (let o = 0; o <= b.length - 16; o++) {
        if (b[o] !== pattern[0]) continue;
        let matches = true;
        for (let j = 1; j < 16; j++) if (b[o + j] !== pattern[j]) { matches = false; break; }
        if (matches && !rows.some(r => r.value === k.value && r.offset === o)) {
          clues.push({ value: k.value, label: k.label, offset: o, kind: 'binary' });
        }
      }
    }
    // Printable GUIDs are clues only; never promote an arbitrary IID to CLSID.
    const pattern = /[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/g;
    let clipped = false;
    const addText = (text, scale, base, encoding) => {
      let m;
      pattern.lastIndex = 0;
      while ((m = pattern.exec(text))) {
        if (clues.length >= 256) { clipped = true; break; }
        const offset = base + m.index * scale, value = '{' + m[0].toUpperCase() + '}';
        if (!rows.some(r => r.value === value) && !clues.some(c => c.value === value)) clues.push({ value, offset, kind: 'text', label: encoding });
      }
    };
    addText(new TextDecoder('latin1').decode(b), 1, 0, 'ASCII GUID');
    for (const base of [0, 1]) {
      const end = b.length - ((b.length - base) % 2);
      if (end > base) addText(new TextDecoder('utf-16le').decode(b.subarray(base, end)), 2, base, 'UTF-16LE GUID');
    }
    if (clipped) warnings.push('Text GUID clues are limited to 256 entries.');
    const decoders = rows.filter(r => /decoder/i.test(r.name) && !/property/i.test(r.name));
    const unnamedSections = sections.filter(s => !s.name).length;
    if (!rows.length && unnamedSections >= 2 && unnamedSections * 2 >= sections.length) {
      warnings.push('Most PE section names are missing; a packed or protected factory layout may not be statically readable.');
    }
    const knownClues = clues.filter(c => c.kind === 'binary' && KNOWN.some(k => k.value === c.value));
    const hasClassFactoryExport = exports.some(e => e.name === 'DllGetClassObject' && !e.forwarded);
    const knownDecoderClue = !rows.length && hasClassFactoryExport && new Set(knownClues.map(c => c.value)).size === 1 ? knownClues[0] : null;
    return { format: is64 ? 'PE32+' : 'PE32', machine: u16(pe + 4), imageBase: '0x' + hex(imageBase), size: b.length, sections, exports, rows, clues, warnings, primary: decoders.length === 1 ? decoders[0] : null, knownDecoderClue };
  }
  const api = { parsePE, guidBytes, KNOWN, MAX_SIZE, hex };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ClvsdScanner = api;
})(globalThis);
