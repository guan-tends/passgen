const { test, describe } = require('node:test');
const assert = require('node:assert');
const {
  cyrb53, cyrb128, sfc32, sfc32Factory, sha3,
  rehash0, rehash1, extendWord,
  generatePassword, derivePassword, getSalt,
  EMOJI_UNICODE, SYMBOLS,
} = require('../passgen.js');

// ── Primitive Tests ───────────────────────────────────

describe('cyrb53', () => {
  test('returns consistent number for same input', () => {
    const a = cyrb53('hello');
    const b = cyrb53('hello');
    assert.strictEqual(a, b);
    assert.strictEqual(typeof a, 'number');
  });

  test('different inputs produce different outputs', () => {
    const a = cyrb53('hello');
    const b = cyrb53('world');
    assert.notStrictEqual(a, b);
  });

  test('seed changes output', () => {
    const a = cyrb53('hello');
    const b = cyrb53('hello', 42);
    assert.notStrictEqual(a, b);
  });
});

describe('cyrb128', () => {
  test('returns 4-element array', () => {
    const r = cyrb128('test');
    assert.strictEqual(r.length, 4);
    r.forEach(x => assert.strictEqual(typeof x, 'number'));
  });

  test('deterministic', () => {
    assert.deepStrictEqual(cyrb128('abc'), cyrb128('abc'));
  });

  test('seed changes output', () => {
    const a = cyrb128('abc');
    const b = cyrb128('abc', [1, 2, 3, 4]);
    assert.notDeepStrictEqual(a, b);
  });
});

describe('sfc32', () => {
  test('produces numbers in [0,1)', () => {
    const rng = sfc32(1, 2, 3, 4);
    for (let i = 0; i < 100; i++) {
      const v = rng();
      assert.ok(v >= 0 && v < 1, `value ${v} out of range`);
    }
  });

  test('deterministic for same seeds', () => {
    const r1 = sfc32(1, 2, 3, 4);
    const r2 = sfc32(1, 2, 3, 4);
    for (let i = 0; i < 10; i++) assert.strictEqual(r1(), r2());
  });
});

describe('sfc32Factory', () => {
  test('accepts string seeds', () => {
    const rng = sfc32Factory('hello');
    assert.strictEqual(typeof rng(), 'number');
  });

  test('accepts hex string seeds', () => {
    const rng = sfc32Factory('deadbeef12345678');
    const v = rng();
    assert.ok(v >= 0 && v < 1);
  });
});

describe('sha3', () => {
  test('returns 64-char hex', () => {
    const h = sha3('hello');
    assert.strictEqual(h.length, 64);
    assert.match(h, /^[0-9a-f]+$/);
  });

  test('same input same output', () => {
    assert.strictEqual(sha3('hello'), sha3('hello'));
  });
});

describe('rehash0', () => {
  test('returns n results', () => {
    const r = rehash0('x', 3, sha3);
    assert.strictEqual(r.length, 3);
    r.forEach(h => assert.strictEqual(h.length, 64));
  });

  test('each element is hash of prior', () => {
    const r = rehash0('x', 2, sha3);
    assert.strictEqual(r[1], sha3(r[0]));
  });
});

describe('rehash1', () => {
  test('chains n times', () => {
    const r = rehash1('x', 3, sha3);
    assert.strictEqual(r, sha3(sha3(sha3('x'))));
  });

  test('zero rounds returns empty', () => {
    assert.strictEqual(rehash1('x', 0, sha3), '');
  });
});

describe('extendWord', () => {
  test('extends deterministically', () => {
    const a = extendWord('short', 'deadbeef', 50);
    const b = extendWord('short', 'deadbeef', 50);
    assert.strictEqual(a, b);
    assert.ok(a.length >= 50);
  });

  test('no extension if already long enough', () => {
    const long = 'a'.repeat(100);
    const r = extendWord(long, 'seed', 50);
    assert.strictEqual(r, long);
  });
});

// ── Generator Tests ───────────────────────────────────

describe('getSalt', () => {
  test('returns consistent salt', () => {
    assert.strictEqual(getSalt(), getSalt());
  });
});

describe('generatePassword', () => {
  test('produces exact requested length', () => {
    const p = generatePassword({
      uri: 'svc', user: 'u', secret: 'secret',
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      lengthOption: 64, symbolRatio: 0, emojiRatio: 0,
    });
    assert.strictEqual(p.length, 64);
  });

  test('produces 128-char when requested', () => {
    const p = generatePassword({
      uri: 'svc', user: 'u', secret: 'secret',
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      lengthOption: 128, symbolRatio: 0, emojiRatio: 0,
    });
    assert.strictEqual(p.length, 128);
  });

  test('deterministic for same inputs', () => {
    const opts = {
      uri: 'svc', user: 'u', secret: 'secret',
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      lengthOption: 32, symbolRatio: 0, emojiRatio: 0,
    };
    assert.strictEqual(generatePassword(opts), generatePassword({ ...opts }));
  });

  test('different URIs produce different outputs', () => {
    const base = {
      user: 'u', secret: 'secret',
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      lengthOption: 32, symbolRatio: 0, emojiRatio: 0,
    };
    assert.notStrictEqual(generatePassword({ ...base, uri: 'a' }), generatePassword({ ...base, uri: 'b' }));
  });

  test('different secrets produce different outputs', () => {
    const base = {
      uri: 'svc', user: 'u',
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      lengthOption: 32, symbolRatio: 0, emojiRatio: 0,
    };
    assert.notStrictEqual(generatePassword({ ...base, secret: 'a' }), generatePassword({ ...base, secret: 'b' }));
  });

  test('caps option introduces uppercase', () => {
    const p = generatePassword({
      uri: 'svc', user: 'u', secret: 'secret',
      useSymbols: false, useCapitalLetters: true, useEmoji: false,
      lengthOption: 64, symbolRatio: 0, emojiRatio: 0,
    });
    // Probabilistic: with 50% per char, 64 chars → ~32 uppercase expected. Very unlikely to have 0.
    assert.ok(/[A-Z]/.test(p), 'Expected at least one uppercase letter');
  });

  test('symbols option introduces symbols', () => {
    const p = generatePassword({
      uri: 'svc', user: 'u', secret: 'secret',
      useSymbols: true, useCapitalLetters: false, useEmoji: false,
      lengthOption: 64, symbolRatio: 1.0, emojiRatio: 0,
    });
    assert.ok(
      [...p].some(c => SYMBOLS.includes(c)),
      'Expected at least one symbol with ratio=1.0'
    );
  });

  test('emoji option does not break length', () => {
    const p = generatePassword({
      uri: 'svc', user: 'u', secret: 'secret',
      useSymbols: false, useCapitalLetters: false, useEmoji: true,
      lengthOption: 64, symbolRatio: 0, emojiRatio: 0.5,
    });
    assert.strictEqual(p.length, 64);
    // At least some emoji should appear (probabilistic but likely with ratio=0.5)
    const hasEmoji = [...p].some(c => EMOJI_UNICODE.includes(c));
    assert.ok(hasEmoji, 'Expected at least one emoji with ratio=0.5');
  });
});

describe('derivePassword', () => {
  test('produces exact length', () => {
    const p = derivePassword({
      uri: 'github', user: 'test', secret: 'master123',
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      lengthOption: 64, symbolRatio: 0, emojiRatio: 0,
    });
    assert.strictEqual(p.length, 64);
  });

  test('deterministic across calls', () => {
    const opts = {
      uri: 'github', user: 'test', secret: 'master123',
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      lengthOption: 32, symbolRatio: 0, emojiRatio: 0,
    };
    assert.strictEqual(derivePassword({ ...opts }), derivePassword({ ...opts }));
  });

  test('different services produce different passwords', () => {
    const base = {
      user: 'test', secret: 'master123',
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      lengthOption: 32, symbolRatio: 0, emojiRatio: 0,
    };
    assert.notStrictEqual(
      derivePassword({ ...base, uri: 'github' }),
      derivePassword({ ...base, uri: 'gitlab' })
    );
  });

  test('different masters produce different passwords', () => {
    const base = {
      uri: 'github', user: 'test',
      useSymbols: false, useCapitalLetters: false, useEmoji: false,
      lengthOption: 32, symbolRatio: 0, emojiRatio: 0,
    };
    assert.notStrictEqual(
      derivePassword({ ...base, secret: 'aaa' }),
      derivePassword({ ...base, secret: 'bbb' })
    );
  });

  test('full options run without error', () => {
    const p = derivePassword({
      uri: 'bank.example.com', user: 'freeman',
      secret: 'my_brain_wallet_phrase_123',
      useSymbols: true, useCapitalLetters: true, useEmoji: false,
      lengthOption: 48, symbolRatio: 0.32, emojiRatio: 0,
    });
    assert.strictEqual(p.length, 48);
    assert.ok(/[A-Z]/.test(p));
    assert.ok([...p].some(c => SYMBOLS.includes(c)));
  });
});
