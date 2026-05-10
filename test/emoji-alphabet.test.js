const { test, describe } = require('node:test');
const assert = require('node:assert');
const {
  generateEmojiPhrase,
  estimateEmojiPhraseEntropy,
  EMOJI_ALPHABET,
  EMOJI_ALPHABET_FLAT,
  EMOJI_ALPHABET_SIZE,
} = require('../passgen.js');

// ── Emoji Alphabet Structure ──────────────────────────

describe('EMOJI_ALPHABET structure', () => {
  test('has all five categories', () => {
    assert.deepStrictEqual(Object.keys(EMOJI_ALPHABET).sort(), ['creatures', 'nature', 'objects', 'places', 'remainder']);
  });

  test('nature has 128 symbols', () => {
    assert.strictEqual(EMOJI_ALPHABET.nature.length, 128);
  });

  test('creatures has 128 symbols', () => {
    assert.strictEqual(EMOJI_ALPHABET.creatures.length, 128);
  });

  test('objects has 128 symbols', () => {
    assert.strictEqual(EMOJI_ALPHABET.objects.length, 128);
  });

  test('places has 128 symbols', () => {
    assert.strictEqual(EMOJI_ALPHABET.places.length, 128);
  });

  test('remainder is defined', () => {
    assert.ok(EMOJI_ALPHABET.remainder.length > 0);
  });

  test('flattened array matches total size', () => {
    assert.strictEqual(EMOJI_ALPHABET_FLAT.length, EMOJI_ALPHABET_SIZE);
  });

  test('all entries are single strings', () => {
    EMOJI_ALPHABET_FLAT.forEach((sym, i) => {
      assert.strictEqual(typeof sym, 'string', `Entry ${i} is not a string`);
      assert.strictEqual([...sym].length, 1, `Entry ${i} is multi-codepoint: ${sym}`);
    });
  });
});

// ── generateEmojiPhrase ───────────────────────────────

describe('generateEmojiPhrase', () => {
  test('returns a string', () => {
    const phrase = generateEmojiPhrase('test', 12);
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

  test('is deterministic for same master', () => {
    const a = generateEmojiPhrase('same-secret', 12);
    const b = generateEmojiPhrase('same-secret', 12);
    assert.strictEqual(a, b);
  });

  test('produces different phrases for different masters', () => {
    const a = generateEmojiPhrase('secret-a', 12);
    const b = generateEmojiPhrase('secret-b', 12);
    assert.notStrictEqual(a, b);
  });

  test('produces different lengths for different counts', () => {
    const a = generateEmojiPhrase('same', 8);
    const b = generateEmojiPhrase('same', 12);
    assert.notStrictEqual(a, b);
  });

  test('all symbols are from the alphabet', () => {
    const phrase = generateEmojiPhrase('alphabet-test', 12);
    const symbols = phrase.split(' ');
    symbols.forEach(s => {
      assert.ok(EMOJI_ALPHABET_FLAT.includes(s), `Unknown symbol: ${s}`);
    });
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

  test('12 symbols yields ~116 bits (for 857-symbol set)', () => {
    const bits = estimateEmojiPhraseEntropy(12);
    const expected = Math.floor(12 * Math.log2(857));
    assert.strictEqual(bits, expected);
  });
});

// ── Cross-category distribution smoke test ─────────────

describe('Distribution smoke test', () => {
  test('generates symbols from multiple categories across many runs', () => {
    const usedCategories = new Set();
    for (let i = 0; i < 100; i++) {
      const phrase = generateEmojiPhrase('\'dist-test-' + i + '\'', 12);
      const symbols = phrase.split(' ');
      symbols.forEach(s => {
        Object.entries(EMOJI_ALPHABET).forEach(([cat, list]) => {
          if (list.includes(s)) usedCategories.add(cat);
        });
      });
    }
    // Should see symbols from at least 3 categories in 100 runs
    assert.ok(usedCategories.size >= 3, `Only saw ${usedCategories.size} categories: ${[...usedCategories].join(', ')}`);
  });
});
