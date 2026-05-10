const { test, describe } = require('node:test');
const assert = require('node:assert');
const {
  generateSeedPhrase,
  validateMnemonic,
  BIP39_WORDLIST,
  BIP39_CONFIG,
} = require('../passgen.js');

// ── BIP-39 Test Vectors (official spec) ───────────────

const OFFICIAL_VECTORS = [
  {
    entropy: '00000000000000000000000000000000',
    mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  },
];

// ── generateSeedPhrase ────────────────────────────────

describe('generateSeedPhrase', () => {
  test('returns a string', () => {
    const phrase = generateSeedPhrase('test-secret', 12);
    assert.strictEqual(typeof phrase, 'string');
  });

  test('produces correct word count for all sizes', () => {
    [12, 15, 18, 21, 24].forEach(count => {
      const phrase = generateSeedPhrase('count-test', count);
      const words = phrase.split(' ');
      assert.strictEqual(words.length, count, `Expected ${count} words`);
    });
  });

  test('default word count is 24', () => {
    const phrase = generateSeedPhrase('default-test');
    assert.strictEqual(phrase.split(' ').length, 24);
  });

  test('is deterministic for same master', () => {
    const a = generateSeedPhrase('deterministic-master', 24);
    const b = generateSeedPhrase('deterministic-master', 24);
    assert.strictEqual(a, b);
  });

  test('produces different phrases for different masters', () => {
    const a = generateSeedPhrase('master-a', 24);
    const b = generateSeedPhrase('master-b', 24);
    assert.notStrictEqual(a, b);
  });

  test('produces different phrases for different word counts', () => {
    const a = generateSeedPhrase('same-master', 12);
    const b = generateSeedPhrase('same-master', 15);
    assert.notStrictEqual(a, b);
  });

  test('all words exist in the BIP-39 wordlist', () => {
    const phrase = generateSeedPhrase('wordlist-test', 24);
    const words = phrase.split(' ');
    words.forEach(w => assert(BIP39_WORDLIST.includes(w), `Missing word: ${w}`));
  });

  test('throws for invalid word count', () => {
    assert.throws(() => generateSeedPhrase('test', 13), /Invalid wordCount/);
    assert.throws(() => generateSeedPhrase('test', 0), /Invalid wordCount/);
    assert.throws(() => generateSeedPhrase('test', 100), /Invalid wordCount/);
  });
});

// ── validateMnemonic ─────────────────────────────────

describe('validateMnemonic', () => {
  test('validates official test vector', () => {
    const vector = OFFICIAL_VECTORS[0];
    assert.strictEqual(validateMnemonic(vector.mnemonic), true);
  });

  test('validates generated phrases', () => {
    [12, 15, 18, 21, 24].forEach(count => {
      const phrase = generateSeedPhrase('validation-test', count);
      assert.strictEqual(validateMnemonic(phrase), true, `Failed for ${count} words`);
    });
  });

  test('rejects phrase with invalid word', () => {
    const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz';
    assert.strictEqual(validateMnemonic(phrase), false);
  });

  test('rejects phrase with wrong word count', () => {
    const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
    assert.strictEqual(validateMnemonic(phrase), false);
  });

  test('rejects phrase with bad checksum', () => {
    // "about" has the correct checksum for 12x "abandon"
    // "abandon" as the 12th word would have a different checksum
    const bad = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
    assert.strictEqual(validateMnemonic(bad), false);
  });

  test('handles extra whitespace', () => {
    const phrase = '  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  about  ';
    assert.strictEqual(validateMnemonic(phrase), true);
  });
});

// ── Round-trip ───────────────────────────────────────

describe('Round-trip', () => {
  test('generated phrase validates', () => {
    const phrase = generateSeedPhrase('round-trip-master', 24);
    assert.strictEqual(validateMnemonic(phrase), true);
  });

  test('reproducible across identical calls', () => {
    const p1 = generateSeedPhrase('reproducible', 12);
    const p2 = generateSeedPhrase('reproducible', 12);
    assert.strictEqual(p1, p2);
    assert.strictEqual(validateMnemonic(p1), true);
    assert.strictEqual(validateMnemonic(p2), true);
  });
});
