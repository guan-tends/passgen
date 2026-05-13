const { test, describe } = require('node:test');
const assert = require('node:assert');
const {
  generateEmojiPhrase,
  estimateEmojiPhraseEntropy,
  EMOJI_SETS,
} = require('../passgen.js');

// ── EMOJI_SETS Structure ──────────────────────────────

describe('EMOJI_SETS structure', () => {
  test('has all four canonical sets', () => {
    assert.deepStrictEqual(Object.keys(EMOJI_SETS).sort(), ['emoji-1024', 'emoji-2048', 'emoji-256', 'emoji-512']);
  });

  test('emoji-256: size 256, 8 bits', () => {
    assert.strictEqual(EMOJI_SETS['emoji-256'].size, 256);
    assert.strictEqual(EMOJI_SETS['emoji-256'].bits, 8);
    assert.strictEqual(EMOJI_SETS['emoji-256'].symbols.length, 256);
  });

  test('emoji-512: size 512, 9 bits', () => {
    assert.strictEqual(EMOJI_SETS['emoji-512'].size, 512);
    assert.strictEqual(EMOJI_SETS['emoji-512'].bits, 9);
    assert.strictEqual(EMOJI_SETS['emoji-512'].symbols.length, 512);
  });

  test('emoji-1024: size 1024, 10 bits', () => {
    assert.strictEqual(EMOJI_SETS['emoji-1024'].size, 1024);
    assert.strictEqual(EMOJI_SETS['emoji-1024'].bits, 10);
    assert.strictEqual(EMOJI_SETS['emoji-1024'].symbols.length, 1024);
  });

  test('emoji-2048: size 2048, 11 bits', () => {
    assert.strictEqual(EMOJI_SETS['emoji-2048'].size, 2048);
    assert.strictEqual(EMOJI_SETS['emoji-2048'].bits, 11);
    assert.strictEqual(EMOJI_SETS['emoji-2048'].symbols.length, 2048);
  });

  test('derived sets match declared size', () => {
    for (const setId of Object.keys(EMOJI_SETS)) {
      const set = EMOJI_SETS[setId];
      assert.strictEqual(set.symbols.length, set.size, `${setId} length mismatch`);
    }
  });

  test('all entries are single codepoint', () => {
    for (const setId of Object.keys(EMOJI_SETS)) {
      const set = EMOJI_SETS[setId];
      set.symbols.forEach((sym, i) => {
        assert.strictEqual(typeof sym, 'string', `${setId}[${i}] is not a string`);
        const graphemes = [...sym];
        assert.strictEqual(graphemes.length, 1, `${setId}[${i}] is multi-codepoint: ${sym}`);
        const cp = sym.codePointAt(0);
        assert.ok(cp >= 0x2600 && cp <= 0x1F9FF, `${setId}[${i}] codepoint ${cp.toString(16)} out of emoji range`);
      });
    }
  });
});

// ── generateEmojiPhrase ───────────────────────────────

describe('generateEmojiPhrase', () => {
  test('returns a string', () => {
    const phrase = generateEmojiPhrase('test', 4);
    assert.strictEqual(typeof phrase, 'string');
  });

  test('produces correct symbol count', () => {
    [1, 4, 8, 12, 24, 48, 64].forEach(count => {
      const phrase = generateEmojiPhrase('count-test', count);
      const symbols = phrase.split(' ');
      assert.strictEqual(symbols.length, count, `Expected ${count} symbols`);
    });
  });

  test('default symbol count is 12', () => {
    const phrase = generateEmojiPhrase('default-test');
    assert.strictEqual(phrase.split(' ').length, 12);
  });

  test('default set is emoji-1024', () => {
    const plain = generateEmojiPhrase('test', 8);
    const explicit = generateEmojiPhrase('test', 8, 'emoji-1024');
    assert.strictEqual(plain, explicit);
  });

  test('is deterministic for same master + set', () => {
    const a = generateEmojiPhrase('same-secret', 12, 'emoji-1024');
    const b = generateEmojiPhrase('same-secret', 12, 'emoji-1024');
    assert.strictEqual(a, b);
  });

  test('produces different phrases for different masters', () => {
    const a = generateEmojiPhrase('secret-a', 12, 'emoji-1024');
    const b = generateEmojiPhrase('secret-b', 12, 'emoji-1024');
    assert.notStrictEqual(a, b);
  });

  test('produces different phrases for different sets', () => {
    const a = generateEmojiPhrase('same', 8, 'emoji-256');
    const b = generateEmojiPhrase('same', 8, 'emoji-512');
    const c = generateEmojiPhrase('same', 8, 'emoji-1024');
    assert.notStrictEqual(a, b);
    assert.notStrictEqual(b, c);
  });

  test('produces different phrases for different salt', () => {
    const a = generateEmojiPhrase('salted', 8, 'emoji-1024', 'salt');
    const b = generateEmojiPhrase('salted', 8, 'emoji-1024', 'different');
    assert.notStrictEqual(a, b);
  });

  test('all symbols are from the specified set', () => {
    for (const setId of ['emoji-256', 'emoji-512', 'emoji-1024', 'emoji-2048']) {
      const phrase = generateEmojiPhrase('alphabet-test', 12, setId);
      const symbols = phrase.split(' ');
      const setSymbols = new Set(EMOJI_SETS[setId].symbols);
      symbols.forEach(s => {
        assert.ok(setSymbols.has(s), `Unknown symbol in ${setId}: ${s}`);
      });
    }
  });

  test('throws for missing master', () => {
    assert.throws(() => generateEmojiPhrase(''), /Master secret is required/);
  });

  test('throws for symbolCount below 1', () => {
    assert.throws(() => generateEmojiPhrase('test', 0), /symbolCount must be between 1 and 64/);
  });

  test('throws for symbolCount above 64', () => {
    assert.throws(() => generateEmojiPhrase('test', 65), /symbolCount must be between 1 and 64/);
  });

  test('throws for unknown set identifier', () => {
    assert.throws(() => generateEmojiPhrase('test', 4, 'emoji-9999'), /Invalid symbol set/);
  });

  // ── Deterministic fixtures (DEME Draft 00) ──────────
  test('deterministic: test / 4 / emoji-1024', () => {
    assert.strictEqual(generateEmojiPhrase('test', 4, 'emoji-1024'), '\u{1F355} \u{1F3A7} \u{1F64B} \u{1F48E}');
  });

  test('deterministic: test / 8 / emoji-256', () => {
    assert.strictEqual(generateEmojiPhrase('test', 8, 'emoji-256'), '\u{1F343} \u{1F337} \u{1F434} \u{1F3C1} \u{1F38F} \u{1F335} \u{1F441} \u{1F356}');
  });

  test('deterministic: test / 8 / emoji-512', () => {
    assert.strictEqual(generateEmojiPhrase('test', 8, 'emoji-512'), '\u{1F337} \u{1F51F} \u{1F4FA} \u{1F482} \u{1F4C0} \u{1F504} \u{1F505} \u{1F529}');
  });

  test('deterministic: test / 8 / emoji-1024', () => {
    assert.strictEqual(generateEmojiPhrase('test', 8, 'emoji-1024'), '\u{1F355} \u{1F3A7} \u{1F64B} \u{1F48E} \u{1F4D9} \u{1F470} \u{1F386} \u{1F4A7}');
  });

  test('deterministic: test / 8 / emoji-2048', () => {
    assert.strictEqual(generateEmojiPhrase('test', 8, 'emoji-2048'), '\u{1F4BA} \u{1F417} \u{1F604} \u{1F567} \u{26C4} \u{1F564} \u{1F480} \u{1F48B}');
  });

  test('deterministic: same-secret / 12 / emoji-1024', () => {
    assert.strictEqual(generateEmojiPhrase('same-secret', 12, 'emoji-1024'), '\u{1F3B6} \u{1F4A4} \u{1F419} \u{1F47A} \u{1F353} \u{1F402} \u{1F44C} \u{1F4BD} \u{1F615} \u{1F332} \u{1F4F9} \u{1F3D2}');
  });

  test('deterministic: salt changes output', () => {
    const withSalt = generateEmojiPhrase('salted', 8, 'emoji-1024', 'salt');
    const noSalt = generateEmojiPhrase('salted', 8, 'emoji-1024');
    assert.notStrictEqual(withSalt, noSalt);
    assert.strictEqual(withSalt, '\u{2615} \u{1F491} \u{1F62E} \u{1F466} \u{1F4D9} \u{1F462} \u{1F488} \u{1F4DD}');
  });
});

// ── entropy estimation ─────────────────────────────────

describe('estimateEmojiPhraseEntropy', () => {
  test('returns a number', () => {
    const bits = estimateEmojiPhraseEntropy(12);
    assert.strictEqual(typeof bits, 'number');
    assert.ok(bits > 0);
  });

  test('scales with symbolCount', () => {
    const e8 = estimateEmojiPhraseEntropy(8);
    const e12 = estimateEmojiPhraseEntropy(12);
    const e24 = estimateEmojiPhraseEntropy(24);
    assert.ok(e8 < e12, '8 symbols < 12 symbols');
    assert.ok(e12 < e24, '12 symbols < 24 symbols');
  });

  test('12 symbols yields ~120 bits (for 1024-symbol set)', () => {
    const bits = estimateEmojiPhraseEntropy(12, 'emoji-1024');
    assert.strictEqual(bits, 120);
  });

  test('entropy scales with set size', () => {
    const e256 = estimateEmojiPhraseEntropy(8, 'emoji-256');
    const e1024 = estimateEmojiPhraseEntropy(8, 'emoji-1024');
    const e2048 = estimateEmojiPhraseEntropy(8, 'emoji-2048');
    assert.ok(e256 < e1024, '256 < 1024');
    assert.ok(e1024 < e2048, '1024 < 2048');
  });
});

// ── Cross-set distribution smoke test ─────────────────

describe('Distribution smoke test', () => {
  test('generates symbols from multiple categories across many runs', () => {
    const usedPrefixes = new Set();
    for (let i = 0; i < 100; i++) {
      const phrase = generateEmojiPhrase('dist-test-' + i, 12, 'emoji-1024');
      const symbols = phrase.split(' ');
      symbols.forEach(s => {
        const cp = s.codePointAt(0);
        usedPrefixes.add(Math.floor(cp / 0x100));
      });
    }
    assert.ok(usedPrefixes.size >= 5, `Only saw ${usedPrefixes.size} prefix ranges`);
  });
});
