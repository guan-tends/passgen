/**
 * Phase 2 — Security Hardening Tests
 * Delimiters, collision resistance, entropy metering, version param
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  generatePassword, derivePassword,
  buildHashSeed,
  estimateMasterEntropy, estimatePasswordEntropy, classifyStrength,
  buildAuditDigest,
} = require('../passgen');

describe('Phase 2: Delimiter / Collision Resistance', () => {
  it('version 2 changes output compared to version 1 for same inputs', () => {
    const base = {
      uri: 'service', user: 'test', secret: 'master',
      lengthOption: 32,
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      symbolRatio: 0, emojiRatio: 0,
    };
    const v1 = generatePassword({ ...base, version: 1 });
    const v2 = generatePassword({ ...base, version: 2 });
    assert.notStrictEqual(v1, v2, 'v1 and v2 must produce different outputs');
  });

  it('version 2 prevents collision between (ba, nk) and (b, ank)', () => {
    // Without delimiters: 'ba' + 'nk' + 'secret' = 'bank...secret'
    //                    'b'  + 'ank' + 'secret' = 'bank...secret' ← same!
    const a = generatePassword({
      uri: 'ba', user: 'nk', secret: 'secret',
      lengthOption: 32, useSymbols: false, useCapitalLetters: false, useEmoji: false,
      symbolRatio: 0, emojiRatio: 0, version: 2,
    });
    const b = generatePassword({
      uri: 'b', user: 'ank', secret: 'secret',
      lengthOption: 32, useSymbols: false, useCapitalLetters: false, useEmoji: false,
      symbolRatio: 0, emojiRatio: 0, version: 2,
    });
    assert.notStrictEqual(a, b, 'Delimiter must distinguish different segmentations');
  });

  it('version 1 legacy encoding has the collision vulnerability', () => {
    const a = generatePassword({
      uri: 'ba', user: 'nk', secret: 'secret',
      lengthOption: 32, useSymbols: false, useCapitalLetters: false, useEmoji: false,
      symbolRatio: 0, emojiRatio: 0, version: 1,
    });
    const b = generatePassword({
      uri: 'b', user: 'ank', secret: 'secret',
      lengthOption: 32, useSymbols: false, useCapitalLetters: false, useEmoji: false,
      symbolRatio: 0, emojiRatio: 0, version: 1,
    });
    assert.strictEqual(a, b, 'Legacy concat should collide for ba+nk vs b+ank');
  });

  it('buildHashSeed v2 produces stable output with tab prefix + null delimiters', () => {
    const seed = buildHashSeed({ uri: 's', user: 'u', secret: 'p', version: 2 });
    assert.strictEqual(seed.startsWith('\t'), true, 'v2 seed starts with tab');
    assert.ok(seed.includes('\0'), 'v2 seed contains null delimiters');
  });

  it('buildHashSeed v1 produces bare concatenation', () => {
    const seed = buildHashSeed({ uri: 's', user: 'u', secret: 'p', version: 1 });
    assert.strictEqual(seed, 'sup' + seed.slice(3), 'v1 seed is plain concatenation');
    assert.ok(!seed.startsWith('\t'), 'v1 seed has no tab prefix');
  });
});

describe('Phase 2: Entropy Estimation', () => {
  it('estimateMasterEntropy returns 0 for empty string', () => {
    assert.strictEqual(estimateMasterEntropy(''), 0);
  });

  it('estimateMasterEntropy rises with length and charset', () => {
    const low = estimateMasterEntropy('abc');
    const med = estimateMasterEntropy('abc123');
    const high = estimateMasterEntropy('abc123!@#');
    assert.ok(low > 0);
    assert.ok(med > low, 'more chars = more entropy');
    assert.ok(high > med, 'symbols add entropy');
  });

  it('estimatePasswordEntropy is within reasonable bounds', () => {
    const short = generatePassword({
      uri: 'a', user: 'b', secret: 'c',
      lengthOption: 16, useSymbols: false, useCapitalLetters: false, useEmoji: false,
      symbolRatio: 0, emojiRatio: 0, version: 2,
    });
    const long = generatePassword({
      uri: 'a', user: 'b', secret: 'c',
      lengthOption: 64, useSymbols: true, useCapitalLetters: true, useEmoji: false,
      symbolRatio: 0.5, emojiRatio: 0, version: 2,
    });
    assert.ok(estimatePasswordEntropy(short) >= 16);
    assert.ok(estimatePasswordEntropy(long) > estimatePasswordEntropy(short), 'longer = more entropy');
  });

  it('classifyStrength buckets appropriately', () => {
    assert.ok(classifyStrength(220).includes('Very Strong'));
    assert.ok(classifyStrength(160).includes('Strong'));
    assert.ok(classifyStrength(110).includes('Moderate'));
    assert.ok(classifyStrength(70).includes('Weak'));
    assert.ok(classifyStrength(30).includes('Very Weak'));
  });
});

describe('Phase 2: Audit Digest', () => {
  it('buildAuditDigest is deterministic for identical parameters', () => {
    const params = { uri: 'svc', user: 'me', secret: 'X', lengthOption: 32, useSymbols: false, useCapitalLetters: false, useEmoji: false, symbolRatio: 0, emojiRatio: 0, version: 2 };
    const a = buildAuditDigest(params);
    const b = buildAuditDigest(params);
    assert.strictEqual(a, b);
    assert.strictEqual(a.length, 64, 'audit digest is SHA3-256 hex');
  });

  it('buildAuditDigest excludes secret from hash input', () => {
    const a = buildAuditDigest({ uri: 'svc', user: 'me', secret: 'AAA', lengthOption: 32, useSymbols: false, useCapitalLetters: false, useEmoji: false, symbolRatio: 0, emojiRatio: 0, version: 2 });
    const b = buildAuditDigest({ uri: 'svc', user: 'me', secret: 'BBB', lengthOption: 32, useSymbols: false, useCapitalLetters: false, useEmoji: false, symbolRatio: 0, emojiRatio: 0, version: 2 });
    assert.strictEqual(a, b, 'secret must NOT affect audit digest (privacy)');
  });

  it('buildAuditDigest differs when service changes', () => {
    const base = { user: 'me', secret: 'x', lengthOption: 32, useSymbols: false, useCapitalLetters: false, useEmoji: false, symbolRatio: 0, emojiRatio: 0, version: 2 };
    const a = buildAuditDigest({ ...base, uri: 'svc-a' });
    const b = buildAuditDigest({ ...base, uri: 'svc-b' });
    assert.notStrictEqual(a, b);
  });
});

describe('Phase 2: Version parameter in derivePassword', () => {
  it('derivePassword with version 2 produces different output than version 1', () => {
    const base = {
      uri: 'svc', user: 'me', secret: 'master',
      lengthOption: 32, useSymbols: false, useCapitalLetters: false, useEmoji: false,
      symbolRatio: 0, emojiRatio: 0,
    };
    const v1 = derivePassword({ ...base, version: 1 });
    const v2 = derivePassword({ ...base, version: 2 });
    assert.notStrictEqual(v1, v2);
    assert.strictEqual(v1.length, 32);
    assert.strictEqual(v2.length, 32);
  });
});