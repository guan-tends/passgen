const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  analyzeMasterStrength, formatCrackTime,
  generateDicewareMaster, loadDicewareWordlist,
  checkMasterPwned
} = require('../passgen.js');

describe('Phase 7 — Master Strength Analyzer', () => {
  it('detects "password" as critical dictionary word', () => {
    const r = analyzeMasterStrength('password');
    assert.deepStrictEqual(r.strengthClass, 'very-weak');
    assert.ok(r.warnings.some(w => w.includes('password')));
    assert.ok(r.patternsDetected.some(p => p.type === 'dictionary-word' && p.severity === 'critical'));
  });

  it('penalizes password123 with substitutions and sequences', () => {
    const r = analyzeMasterStrength('password123');
    assert.equal(r.strengthClass, 'very-weak');
    assert.ok(r.warnings.length >= 2);
    // Should detect sequential digits
    assert.ok(r.patternsDetected.some(p => p.type === 'sequential-digits'));
  });

  it('flags keyboard walk qwerty', () => {
    const r = analyzeMasterStrength('myqwertypassword');
    assert.ok(r.patternsDetected.some(p => p.type === 'keyboard-walk'));
  });

  it('flags repeated characters', () => {
    const r = analyzeMasterStrength('aaaabbbbcccc');
    assert.ok(r.patternsDetected.some(p => p.type === 'repeated-char'));
  });

  it('rates a strong passphrase very-strong', () => {
    const r = analyzeMasterStrength('correct horse battery staple');
    assert.equal(r.strengthClass, 'very-strong');
    assert.equal(r.warnings.length, 0);
    assert.ok(r.shannonBits > 80);
  });

  it('penalty reduces adjusted bits below raw bits', () => {
    const r = analyzeMasterStrength('password123');
    assert.ok(r.patternAdjustedBits < r.shannonBits);
  });

  it('formatCrackTime handles all scales', () => {
    assert.equal(formatCrackTime(0.5), '< 1 second');
    assert.equal(formatCrackTime(45), '45 seconds');
    assert.equal(formatCrackTime(1800), '30 minutes');
    assert.equal(formatCrackTime(86400), '24 hours');
    assert.equal(formatCrackTime(31536000), '12 months');
    assert.equal(formatCrackTime(3.154e15), 'heat death of universe');
    assert.equal(formatCrackTime(1e30), 'heat death of universe');
  });
});

describe('Phase 7 — Diceware Master Generator', () => {
  it('loads the EFF wordlist', () => {
    const wl = loadDicewareWordlist();
    assert.equal(wl.length, 7776);
    assert.ok(wl[0].length > 0);
  });

  it('generates the requested word count', () => {
    const r = generateDicewareMaster(6);
    assert.equal(r.words.length, 6);
    assert.equal(r.phrase.split(' ').length, 6);
  });

  it('generates 8-word with ~103 bits', () => {
    const r = generateDicewareMaster(8);
    assert.equal(r.entropyBits, 103);
    assert.equal(r.strengthClass, 'very-strong');
  });

  it('6-word is moderate strength', () => {
    const r = generateDicewareMaster(6);
    assert.equal(r.entropyBits, 77); // floor(6 * 12.925)
    assert.equal(r.strengthClass, 'moderate');
  });

  it('different calls produce different phrases', () => {
    const a = generateDicewareMaster(8);
    const b = generateDicewareMaster(8);
    assert.notEqual(a.phrase, b.phrase);
  });

  it('all words are from the wordlist', () => {
    const wl = loadDicewareWordlist();
    const r = generateDicewareMaster(10);
    for (const w of r.words) {
      assert.ok(wl.includes(w), `word '${w}' not in wordlist`);
    }
  });
});

describe('Phase 7 — HIBP Breach Check', () => {
  it('returns a promise', () => {
    const p = checkMasterPwned('test_not_real');
    assert.ok(p instanceof Promise);
    return p.then(r => {
      assert.ok(typeof r.found === 'boolean');
      assert.ok(typeof r.count === 'number');
    });
  });
});
