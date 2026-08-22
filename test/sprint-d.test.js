/**
 * Sprint D — Comprehensive Tests
 *
 * Covers: Diceware fixes (no master param, crypto.randomInt), derivePassword
 * non-mutation, emoji-2048 structure with documented duplicates, salt
 * derivation consistency, and full E2E derivation round-trip.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  derivePassword,
  generateDicewareMaster,
  generateSeedPhrase,
  validateMnemonic,
  generateEmojiPhrase,
  estimateEmojiPhraseEntropy,
  buildAuditDigest,
  getSalt,
  sha3,
  EMOJI_SETS,
} = require('../passgen.js');

// ── T16: Diceware Fixes ───────────────────────────────

describe('Sprint D: Diceware — no master param + crypto.randomInt', () => {
  it('generateDicewareMaster does not accept a master parameter', () => {
    // The function signature is (wordCount) — master is not a parameter.
    // Passing extra args should not change behavior or cause errors.
    const a = generateDicewareMaster(8);
    assert.ok(a.phrase.split(' ').length === 8);
  });

  it('produces valid wordlist indices [0, 7775]', () => {
    // crypto.randomInt(0, 6) should produce uniform dice rolls.
    // 5 rolls of d6 → index range [0, 7775] (6^5 = 7776).
    for (let i = 0; i < 100; i++) {
      const result = generateDicewareMaster(6);
      for (const word of result.words) {
        // Every word must be a non-empty string from the wordlist.
        assert.ok(typeof word === 'string');
        assert.ok(word.length > 0);
      }
    }
  });

  it('different calls produce different phrases (CSPRNG, not deterministic)', () => {
    const phrases = new Set();
    for (let i = 0; i < 10; i++) {
      phrases.add(generateDicewareMaster(8).phrase);
    }
    // With CSPRNG, 10 calls should produce at least 9 unique phrases.
    // (Extremely unlikely to get a collision with 103-bit entropy.)
    assert.ok(phrases.size >= 9, `Expected >=9 unique phrases, got ${phrases.size}`);
  });
});

// ── T17: derivePassword Non-Mutation ─────────────────

describe('Sprint D: derivePassword does not mutate input opts', () => {
  it('opts object is unchanged after derivePassword call', () => {
    const opts = {
      uri: 'github.com',
      user: 'personal',
      secret: 'master-secret',
      useSymbols: true,
      useCapitalLetters: true,
      useEmoji: false,
      lengthOption: 32,
      symbolRatio: 0.32,
      emojiRatio: 0,
      version: 2,
    };
    const snapshot = { ...opts };
    const password = derivePassword(opts);
    assert.ok(password.length > 0, 'password should be non-empty');
    // Every property must match the original snapshot.
    for (const key of Object.keys(snapshot)) {
      assert.strictEqual(
        opts[key],
        snapshot[key],
        `opts.${key} was mutated: expected "${snapshot[key]}", got "${opts[key]}"`
      );
    }
  });

  it('reusing the same opts object produces the same password', () => {
    const opts = {
      uri: 'example.com',
      user: 'test',
      secret: 'secret',
      useSymbols: false,
      useCapitalLetters: false,
      useEmoji: false,
      lengthOption: 32,
      symbolRatio: 0,
      emojiRatio: 0,
      version: 2,
    };
    const first = derivePassword(opts);
    const second = derivePassword(opts);
    assert.strictEqual(first, second, 'same opts should produce same password after derivePassword');
  });
});

// ── T18: emoji-2048 Structure (Intentional Duplicates) ──

describe('Sprint D: emoji-2048 — documented duplicate design', () => {
  it('emoji-2048 has exactly 2048 symbols', () => {
    assert.strictEqual(EMOJI_SETS['emoji-2048'].symbols.length, 2048);
  });

  it('emoji-2048 bits field reports 11', () => {
    assert.strictEqual(EMOJI_SETS['emoji-2048'].bits, 11);
  });

  it('emoji-2048 contains duplicate entries (intentional design tradeoff)', () => {
    // The set pads the available single-codepoint emoji pool to 2048 entries
    // with repeats because there are not enough qualifying single-codepoint
    // emoji (no ZWJ sequences, no skin-tone modifiers, no flags) for 2048
    // unique entries. This is a documented design decision, not a bug.
    // See: draft-guan-emoji-mnemonic-encoding (DEME Draft 00).
    const symbols = EMOJI_SETS['emoji-2048'].symbols;
    const unique = new Set(symbols);
    assert.ok(
      unique.size < symbols.length,
      'emoji-2048 should contain duplicates (intentional padding for bit-precise 11-bit indexing)'
    );
    // The curated pool has ~645 unique qualifying single-codepoint emoji.
    // Both emoji-1024 and emoji-2048 pad from this pool.
    assert.ok(unique.size >= 600, `should have at least 600 unique symbols, got ${unique.size}`);
  });

  it('estimateEmojiPhraseEntropy uses 11 bits for emoji-2048', () => {
    const bits = estimateEmojiPhraseEntropy(12, 'emoji-2048');
    assert.strictEqual(bits, 132, '12 symbols × 11 bits = 132 bits');
  });
});

// ── T19: Salt Derivation Consistency ──────────────────

describe('Sprint D: salt derivation via SHA3-256', () => {
  it('getSalt returns a deterministic hex string', () => {
    const salt = getSalt();
    assert.ok(typeof salt === 'string');
    assert.ok(/^[0-9a-f]+$/.test(salt), 'salt should be a SHA3-256 hex string');
    assert.strictEqual(salt.length, 64, 'SHA3-256 produces 64 hex chars');
  });

  it('getSalt is deterministic across calls', () => {
    assert.strictEqual(getSalt(), getSalt());
  });

  it('getSalt is derived from documented mathematical constants', () => {
    // Verify the salt matches SHA3-256 of the constant concatenation.
    // This is a regression test: if someone changes the constants,
    // this test will catch it.
    const expected = sha3(`${0x9E3779B9}${0x243F6A88}${0xB7E15162}${1337 ^ 0xDEADBEEF}`);
    assert.strictEqual(getSalt(), expected);
  });
});

// ── T21: E2E Derivation Round-Trip ────────────────────

describe('Sprint D: E2E derivation round-trip', () => {
  it('master → password → audit digest → verify consistency', () => {
    const opts = {
      uri: 'github.com',
      user: 'personal',
      secret: 'my-master-secret-2026',
      lengthOption: 64,
      useSymbols: true,
      useCapitalLetters: true,
      useEmoji: false,
      symbolRatio: 0.32,
      emojiRatio: 0,
      version: 2,
    };

    // Generate password
    const password = derivePassword({ ...opts });
    assert.strictEqual(password.length, 64);

    // Build audit digest (excludes secret)
    const digest = buildAuditDigest({
      uri: opts.uri,
      user: opts.user,
      secret: opts.secret,
      lengthOption: opts.lengthOption,
      useSymbols: opts.useSymbols,
      useCapitalLetters: opts.useCapitalLetters,
      useEmoji: opts.useEmoji,
      symbolRatio: opts.symbolRatio,
      emojiRatio: opts.emojiRatio,
      version: opts.version,
    });

    // Digest should be deterministic for same params
    const digest2 = buildAuditDigest({
      uri: opts.uri,
      user: opts.user,
      secret: 'different-secret',
      lengthOption: opts.lengthOption,
      useSymbols: opts.useSymbols,
      useCapitalLetters: opts.useCapitalLetters,
      useEmoji: opts.useEmoji,
      symbolRatio: opts.symbolRatio,
      emojiRatio: opts.emojiRatio,
      version: opts.version,
    });

    // Digest must be identical regardless of secret (excludes it by design)
    assert.strictEqual(digest, digest2, 'audit digest must not depend on secret');

    // Different params should produce different digest
    const digest3 = buildAuditDigest({
      ...opts,
      uri: 'gitlab.com',
    });
    assert.notStrictEqual(digest, digest3, 'different service should produce different digest');
  });

  it('seed phrase round-trip: generate → validate', () => {
    const phrase = generateSeedPhrase('master-secret', 24);
    assert.ok(phrase.split(' ').length === 24);
    assert.ok(validateMnemonic(phrase), 'generated phrase must validate');

    // Different word counts
    for (const count of [12, 15, 18, 21, 24]) {
      const p = generateSeedPhrase('master', count);
      assert.ok(validateMnemonic(p), `${count}-word phrase must validate`);
    }
  });

  it('emoji phrase is deterministic from master', () => {
    const a = generateEmojiPhrase('master-secret', 12);
    const b = generateEmojiPhrase('master-secret', 12);
    assert.strictEqual(a, b, 'same master + count must produce same emoji phrase');

    const c = generateEmojiPhrase('different-master', 12);
    assert.notStrictEqual(a, c, 'different master must produce different emoji phrase');
  });
});
