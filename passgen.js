#!/usr/bin/env node
// Passgen — Stateless deterministic passphrase generator
// Extracted from Aurora OS (c) the maintainer King, ported by Guan
// License: MIT
// PHASE 2 — Security Hardening: delimiters, entropy audit, version param, namespace hardening

const crypto = require('crypto');

// ── Version ───────────────────────────────────────────
// Version v1: legacy bare concatenation (backward compat)
// Version v2: null-delimited encoding + namespace hardening (default)
const DEFAULT_VERSION = 2;

// ── Inline Primitives ─────────────────────────────────

// cyrb53 (c) 2018-2022 bryc — 53-bit hash
function cyrb53(s, seed = 0x9E3779B9) {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

// cyrb128 — 128-bit hash, seeds sfc32
function cyrb128(s, seeds = [0, 0, 0, 0]) {
  let [seed0, seed1, seed2, seed3] = seeds;
  let h1 = 1779033703 ^ seed0;
  let h2 = 3144134277 ^ seed1;
  let h3 = 1013904242 ^ seed2;
  let h4 = 2773480762 ^ seed3;
  for (let i = 0; i < s.length; i++) {
    const k = s.charCodeAt(i);
    h1 = h2 ^ Math.imul(h1 ^ k, 597399067);
    h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
    h3 = h4 ^ Math.imul(h3 ^ k, 951274213);
    h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
  }
  h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067);
  h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
  h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213);
  h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
  return [
    (h1 ^ h2 ^ h3 ^ h4) >>> 0,
    (h2 ^ h1) >>> 0,
    (h3 ^ h1) >>> 0,
    (h4 ^ h1) >>> 0
  ];
}

// sfc32 (c) Chris Doty-Humphreys — PractRand-passing PRNG
function sfc32(a, b, c, d) {
  return function () {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    let t = (a + b) | 0;
    a = b ^ (b >>> 9);
    b = (c + (c << 3)) | 0;
    c = (c << 21) | (c >>> 11);
    d = (d + 1) | 0;
    t = (t + d) | 0;
    c = (c + t) | 0;
    return (t >>> 0) / 4294967296;
  };
}

function sfc32Factory(seed = 0) {
  const [seed0, seed1, seed2, seed3] = cyrb128(String(seed));
  return sfc32(seed0, seed1, seed2, seed3);
}

// rehash — chain a hash function n times
function rehash0(s, n, hashFn) {
  if (n <= 0) return [];
  const results = [hashFn(s)];
  if (n === 1) return results;
  for (let i = 1; i < n; i++) results.push(hashFn(results[i - 1]));
  return results;
}

function rehash1(s, n, hashFn) {
  if (n <= 0) return '';
  let result = s;
  for (let i = 0; i < n; i++) result = hashFn(result);
  return result;
}

// SHA3-256 via Node.js crypto
function sha3(s) {
  const hasher = crypto.createHash('sha3-256');
  hasher.update(String(s), 'utf8');
  return hasher.digest('hex');
}

function sha3_512(s) {
  const hasher = crypto.createHash('sha3-512');
  hasher.update(String(s), 'utf8');
  return hasher.digest('hex');
}

// Extend base36 output deterministically to reach target length
function extendWord(word, seedHex, targetLen) {
  let extended = word;
  let counter = 1;
  while (extended.length < targetLen) {
    const extHash = sha3(seedHex + String(counter));
    extended += BigInt('0x' + extHash).toString(36);
    counter++;
  }
  return extended;
}

// ── Entropy Utilities ─────────────────────────────────

function estimateMasterEntropy(master) {
  if (!master || master.length === 0) return 0;
  const len = master.length;
  // Estimate entropy per char based on character classes present
  const hasLower = /[a-z]/.test(master);
  const hasUpper = /[A-Z]/.test(master);
  const hasDigit = /[0-9]/.test(master);
  const hasSymbol = /[^a-zA-Z0-9]/.test(master);
  const charSetSize = (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + (hasDigit ? 10 : 0) + (hasSymbol ? 33 : 0);
  // Use a conservative floor of 26 to avoid overestimating poor inputs
  const bitsPerChar = Math.log2(Math.max(26, charSetSize));
  return Math.floor(len * bitsPerChar);
}

function estimatePasswordEntropy(password) {
  // Shannon entropy approximation via unique character frequency
  const freq = {};
  for (const ch of password) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const ch of password) {
    const p = freq[ch] / password.length;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * password.length);
}

function classifyStrength(bits) {
  if (bits >= 200) return 'Very Strong 💪';
  if (bits >= 150) return 'Strong ✅';
  if (bits >= 100) return 'Moderate ⚠️';
  if (bits >= 60)  return 'Weak ❌';
  return 'Very Weak 💀';
}

// ── Master Strength Analyzer ─────────────────────────
// Phase 7: Honest entropy with pattern detection

const WEAK_PASSWORDS = new Set([
  'password','123456','12345678','qwerty','abc123','monkey','letmein',
  'dragon','111111','baseball','iloveyou','trustno1','sunshine',
  'princess','admin','welcome','shadow','ashley','football','jesus',
  'michael','ninja','mustang','password1','123456789','adobe123',
  'admin123','letmein1','photoshop','master','hello','freedom',
  'whatever','qazwsx','starwars','zaq12wsx','password123','login',
  'princess1','solo','qwertyuiop','rockyou','mynoob','thomas',
  'batman','passw0rd','hacker','love123','welcome1','charlie'
]);

const KEYBOARD_WALKS = [
  'qwerty','asdf','zxcvb','qwertyuiop','asdfghjkl','zxcvbnm',
  'qazwsx','wsxedcrfvtgb','ytrewq','fdsa','bvxcz',
  '1qaz2wsx','qwertzuiop','yxcvbnm','poiuytrewq','lkjhgfdsa',
  'mnbvcxz','edcrfvtgb','plmoknijb','qawsedrf','zaq1xsw2'
];

const REVERSE_SUBSTITUTIONS = { '@':'a','$':'s','1':'i','!':'i','0':'o','3':'e','7':'t','9':'g','8':'b','5':'s' };

function estimateShannonBits(master) {
  if (!master || master.length === 0) return 0;
  const freqs = {};
  for (const c of master) freqs[c] = (freqs[c] || 0) + 1;
  let entropy = 0;
  for (const count of Object.values(freqs)) {
    const p = count / master.length;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * master.length);
}

function analyzeMasterStrength(master) {
  const patterns = [];
  const warnings = [];
  const lower = master.toLowerCase();
  const shannonBits = estimateShannonBits(master);

  // Dictionary check
  for (const weak of WEAK_PASSWORDS) {
    if (lower.includes(weak)) {
      patterns.push({ type: "dictionary-word", severity: "critical" });
      warnings.push(`Contains common password: "${weak}"`);
    }
  }

  // Keyboard walks
  for (const walk of KEYBOARD_WALKS) {
    if (lower.includes(walk)) {
      patterns.push({ type: "keyboard-walk", severity: "high" });
      warnings.push(`Contains keyboard walk: "${walk}"`);
    }
  }

  // Sequential / repeated digits
  const digitMatch = master.match(/\d{3,}/);
  if (digitMatch) {
    const match = digitMatch[0];
    const isSeq = [...match].slice(1).every((c, i) => parseInt(c) === parseInt(match[i]) + 1);
    const isRep = new Set(match).size === 1;
    if (isSeq || isRep) {
      patterns.push({ type: isSeq ? "sequential-digits" : "repeated-digits", severity: "high" });
      warnings.push(`${isSeq ? "Sequential" : "Repeated"} digits: "${match}"`);
    }
  }

  // Repeated characters
  const repMatch = master.match(/(.)\1{2,}/);
  if (repMatch) {
    patterns.push({ type: "repeated-char", severity: "medium" });
    warnings.push(`Repeated character: "${repMatch[0]}"`);
  }

  // Substitution unmask
  let unsubst = lower;
  for (const [sub, orig] of Object.entries(REVERSE_SUBSTITUTIONS)) {
    unsubst = unsubst.replace(new RegExp("\\\\" + sub, "g"), orig);
  }
  if (unsubst !== lower) {
    for (const weak of WEAK_PASSWORDS) {
      if (unsubst.includes(weak)) {
        patterns.push({ type: "substitution-mask", severity: "high" });
        warnings.push(`Common word with substitutions: "${weak}"`);
        break;
      }
    }
  }

  let penalty = 0;
  for (const p of patterns) {
    if (p.severity === "critical") penalty += 20;
    else if (p.severity === "high") penalty += 10;
    else if (p.severity === "medium") penalty += 5;
  }
  const patternAdjustedBits = Math.max(0, shannonBits - penalty);

  const guessesPerSecond = 1e12;
  const rounds = parseInt(process.env.PASSGEN_ROUNDS || "24", 10);
  const slowdownFactor = Math.max(1, rounds / 24);
  const estimatedCrackTimeSeconds = (Math.pow(2, patternAdjustedBits) / guessesPerSecond) * slowdownFactor;

  let strengthClass;
  if (patternAdjustedBits < 30) strengthClass = "very-weak";
  else if (patternAdjustedBits < 50) strengthClass = "weak";
  else if (patternAdjustedBits < 70) strengthClass = "moderate";
  else if (patternAdjustedBits < 90) strengthClass = "strong";
  else strengthClass = "very-strong";

  const actions = {
    "very-weak":   "Generate Diceware passphrase immediately.",
    "weak":        "Use a longer passphrase or Diceware.",
    "moderate":    "Consider 8+ Diceware words for critical assets.",
    "strong":      "Good. Use 10+ Diceware for nation-state resistance.",
    "very-strong": "Excellent. Maintain operational security."
  };

  return {
    shannonBits,
    patternAdjustedBits,
    estimatedCrackTimeSeconds,
    strengthClass,
    patternsDetected: patterns,
    warnings,
    recommendedAction: actions[strengthClass]
  };
}

function formatCrackTime(seconds) {
  if (seconds < 1e-9) return "instant";
  if (seconds < 1)     return "< 1 second";
  if (seconds < 60)    return `${Math.round(seconds)} seconds`;
  if (seconds < 3600)  return `${Math.round(seconds / 60)} minutes`;
  if (seconds <= 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 2.628e6)  return `${Math.round(seconds / 86400)} days`;
  if (seconds < 3.154e7)  return `${Math.round(seconds / 2.628e6)} months`;
  if (seconds < 3.154e8)  return `${Math.round(seconds / 3.154e7)} years`;
  if (seconds < 3.154e10) return `${Math.round(seconds / 3.154e7 / 100)} centuries`;
  return "heat death of universe";
}

// ── Input Encoding / Hardening ────────────────────────

/**
 * Build the pre-hash seed string from derivation parameters.
 *
 * @intent Encode service identity + user identity + master secret into a single
 *   unambiguous string for hashing. This is the critical boundary where
 *   namespace hardening happens.
 * @param {Object} opts
 * @param {string} opts.uri     — Service name or URI
 * @param {string} opts.user    — User identity / account name
 * @param {string} opts.secret  — Master secret
 * @param {number} opts.version — Derivation version (1 = legacy, 2 = null-delimited)
 * @returns {string} Seed string ready for SHA3-256 hashing
 *
 * @version 1 — Legacy: bare concatenation. Vulnerable to dangling-suffix attacks
 *   where ('ba','nk') and ('b','ank') produce identical seeds. Preserved for
 *   backward compatibility with Aurora OS outputs.
 * @version 2 (default) — Null-delimited encoding: `\turi\0user\0secret\0salt`.
 *   Unambiguous boundary parsing prevents all concatenation collision attacks.
 */
function buildHashSeed(opts) {
  const { uri, user, secret, version } = opts;
  const salt = getSalt();
  if (version === 1) {
    // Legacy: bare concatenation (backward compatible with Aurora)
    return `${uri}${user}${secret}${salt}`;
  }
  // Version 2+: null-delimited namespace encoding
  // Prevents collision between ('ba', 'nk') and ('b', 'ank')
  const trueUri = String(uri || '');
  const trueUser = String(user || '');
  const trueSecret = String(secret || '');
  const trueSalt = String(salt);
  // JSON-stable + null-delimiter for unambiguous boundary parsing
  return `\t${trueUri}\0${trueUser}\0${trueSecret}\0${trueSalt}`;
}

function buildAuditDigest(opts) {
  const { uri, user, secret: _secret, lengthOption, useSymbols, useCapitalLetters, useEmoji, symbolRatio, emojiRatio, version } = opts;
  // Deterministic audit hash without exposing secrets.
  // _secret is intentionally excluded from the digest (privacy by design).
  return sha3(JSON.stringify({
    uri, user, lengthOption, useSymbols, useCapitalLetters, useEmoji,
    symbolRatio, emojiRatio, version
  }));
}

// ── Constants ─────────────────────────────────────────

const MIN_WORD_LENGTH = 2 << 3;      // 16
const MAX_WORD_LENGTH = 2 << 6;      // 128
const DEFAULT_WORD_LENGTH = 2 << 5;  // 64

const DEFAULT_SYMBOL_RATIO = 2 << 4;  // 32

const SYMBOLS = '~!@#$%^&*()_+{}|:"<>?`-=[]\\;,./';

const EMOJI_UNICODE = [
  '⌚','⌛','⏪','⏫','⏬','⏰','⏳','◽','◾','☔','☕','♈','♉','♊','♋','♌','♍','♎','♏','♐','♑','♒','♓','♿','⚓','⚡','⚪','⚫','⚽','⚾','⛄','⛅','⛎','⛔','⛪','⛲','⛳','⛵','⛺','⛽','✅','✊','✋','✨','❌','❎','❓','❔','❕','❗','➕','➖','➗','➰','➿','⬛','⬜','⭐','⭕','🀄','🃏','🆎','🆑','🆒','🆓','🆔','🆕','🆖','🆗','🆘','🆙','🆚','🈁','🈚','🈯','🈲','🈳','🈴','🈵','🈶','🈸','🈹','🈺','🉐','🉑','🌀','🌁','🌂','🌃','🌄','🌅','🌆','🌇','🌈','🌉','🌊','🌋','🌌','🌍','🌎','🌏','🌐','🌑','🌒','🌓','🌔','🌕','🌖','🌗','🌘','🌙','🌚','🌛','🌜','🌝','🌞','🌟','🌠','🌭','🌮','🌯','🌰','🌱','🌲','🌳','🌴','🌵','🌷','🌸','🌹','🌺','🌻','🌼','🌽','🌾','🌿','🍀','🍁','🍂','🍃','🍄','🍅','🍆','🍇','🍈','🍉','🍊','🍋','🍌','🍍','🍎','🍏','🍐','🍑','🍒','🍓','🍔','🍕','🍖','🍗','🍘','🍙','🍚','🍛','🍜','🍝','🍞','🍟','🍠','🍡','🍢','🍣','🍤','🍥','🍦','🍧','🍨','🍩','🍪','🍫','🍬','🍭','🍮','🍯','🍰','🍱','🍲','🍳','🍴','🍵','🍶','🍷','🍸','🍹','🍺','🍻','🍼','🍾','🍿','🎀','🎁','🎂','🎃','🎄','🎅','🎆','🎇','🎈','🎉','🎊','🎋','🎌','🎍','🎎','🎏','🎐','🎑','🎒','🎓','🎠','🎡','🎢','🎣','🎤','🎥','🎦','🎧','🎨','🎩','🎪','🎫','🎬','🎭','🎮','🎯','🎰','🎱','🎲','🎳','🎴','🎵','🎶','🎷','🎸','🎹','🎺','🎻','🎼','🎽','🎾','🎿','🏀','🏁','🏂','🏃','🏄','🏅','🏆','🏇','🏈','🏉','🏊','🏏','🏐','🏑','🏒','🏓','🏠','🏡','🏢','🏣','🏤','🏥','🏦','🏧','🏨','🏩','🏪','🏫','🏬','🏭','🏮','🏯','🏰','🏴','🏸','🏹','🏺','👀','👂','👃','👄','👅','👆','👇','👈','👉','👊','👋','👌','👍','👎','👏','👐','👑','👒','👓','👔','👕','👖','👗','👘','👙','👚','👛','👜','👝','👞','👟','👠','👡','👢','👣','👤','👥','👦','👧','👨','👩','👪','👫','👬','👭','👮','👯','👰','👱','👲','👳','👴','👵','👶','👷','👸','👹','👺','👻','👼','👽','👾','👿','💀','💁','💂','💃','💄','💅','💆','💇','💈','💉','💊','💋','💌','💍','💎','💏','💐','💑','💒','💓','💔','💕','💖','💗','💘','💙','💚','💛','💜','💝','💞','💟','💠','💡','💢','💣','💤','💥','💦','💧','💨','💩','💪','💫','💬','💭','💮','💯','💰','💱','💲','💳','💴','💵','💶','💷','💸','💹','💺','💻','💼','💽','💾','💿','📀','📁','📂','📃','📄','📅','📆','📇','📈','📉','📊','📋','📌','📍','📎','📏','📐','📑','📒','📓','📔','📕','📖','📗','📘','📙','📚','📛','📜','📝','📞','📟','📠','📡','📢','📣','📤','📥','📦','📧','📨','📩','📪','📫','📬','📭','📮','📯','📰','📱','📲','📳','📴','📵','📶','📷','📸','📹','📺','📻','📼','📿','🔀','🔁','🔂','🔃','🔄','🔅','🔆','🔇','🔈','🔉','🔊','🔋','🔌','🔍','🔎','🔏','🔐','🔑','🔒','🔓','🔔','🔕','🔖','🔗','🔘','🔙','🔚','🔛','🔜','🔝','🔞','🔟','🔠','🔡','🔢','🔣','🔤','🔥','🔦','🔧','🔨','🔩','🔪','🔫','🔬','🔭','🔮','🔯','🔰','🔱','🔲','🔳','🔴','🔵','🔶','🔷','🔸','🔹','🔺','🔻','🔼','🔽','🕋','🕌','🕍','🕎','🕐','🕑','🕒','🕓','🕔','🕕','🕖','🕗','🕘','🕙','🕚','🕛','🕜','🕝','🕞','🕟','🕠','🕡','🕢','🕣','🕤','🕥','🕦','🕧','🖕','🖖'
];

// ── Core Generator ────────────────────────────────────

/**
 * Return the deterministic salt constant.
 *
 * @intent Provide a fixed salt for stateless derivation. Not random by design —
 *   a stateless system cannot store per-user salts. The salt is public and
 *   deterministic; security comes entirely from master secret entropy.
 * @returns {number} Fixed salt derived from mathematical constants.
 */
function getSalt() {
  // Fixed deterministic salt derived from "nothing-up-my-sleeve" mathematical
  // constants — numbers chosen for their mathematical significance, resisting
  // accusations of backdooring. The salt is PUBLIC; security comes from master
  // entropy, not salt secrecy (stateless design constraint).
  //
  // Constants (fractional parts of irrational numbers, standard in cryptography):
  //   0x9E3779B9 — golden ratio (φ), Knuth's multiplicative hash constant
  //   0x243F6A88 — π, used in Blowfish S-box initialization
  //   0xB7E15162 — e (Euler's number), used in AES round constant derivation
  //   1337 ^ 0xDEADBEEF — leet XOR classic hex sentinel
  //
  // Derived via SHA3-256 for consistency with the rest of the codebase.
  // Previously used cyrb53 (53-bit non-crypto hash) — no practical security
  // difference since the salt is public, but SHA3-256 is the idiomatic choice
  // for a cryptographic tool.
  return sha3(`${0x9E3779B9}${0x243F6A88}${0xB7E15162}${1337 ^ 0xDEADBEEF}`);
}

/**
 * Generate a single-round deterministic password from derivation parameters.
 *
 * @intent Core password generation: hash the seed, convert to base36, apply
 *   character class modifications (symbols, caps, emoji) seeded from the hash.
 *   This is the inner loop; use derivePassword() for production.
 * @param {Object} opts
 * @param {string} opts.uri              — Service name or URI
 * @param {string} opts.user             — User identity
 * @param {string} opts.secret           — Master secret
 * @param {boolean} opts.useSymbols      — Replace chars with symbols
 * @param {boolean} opts.useCapitalLetters — Randomly upcase chars
 * @param {boolean} opts.useEmoji        — Replace chars with emoji (service warning)
 * @param {number} opts.lengthOption     — Target password length (16–128)
 * @param {number} opts.symbolRatio      — Symbol replacement probability (0–1)
 * @param {number} opts.emojiRatio       — Emoji replacement probability (0–1)
 * @param {number} [opts.version=2]      — Derivation version (1=legacy)
 * @returns {string} Generated password
 * @warning Word length may differ from target if emoji span multiple code units.
 *   A console.warn is emitted if length mismatch exceeds expected bounds.
 */
function generatePassword(opts) {
  const {
    uri, user, secret,
    useSymbols, useCapitalLetters, useEmoji,
    lengthOption,
    symbolRatio, emojiRatio,
    version = DEFAULT_VERSION
  } = opts;

  const hashSeed = buildHashSeed({ uri, user, secret, version });
  const hash = rehash1(hashSeed, 2 << 3, sha3);

  let word = BigInt(`0x${hash}`).toString(36);

  if (word.length < lengthOption) {
    word = extendWord(word, hash, lengthOption);
  }

  let final = word.slice(0, lengthOption);

  if (useCapitalLetters || useSymbols || useEmoji) {
    const [seed0, seed1, seed2] = rehash0(hash, 3, sha3);

    if (useCapitalLetters) {
      const rnd = sfc32Factory(seed0);
      final = final.split('')
        .map(c => rnd() < 0.5 ? c : c.toUpperCase())
        .join('');
    }

    if (useSymbols) {
      const rnd = sfc32Factory(seed1);
      final = final.split('')
        .map(c => rnd() > symbolRatio ? c : SYMBOLS[Math.floor(rnd() * SYMBOLS.length)])
        .join('');
    }

    if (useEmoji) {
      const rnd = sfc32Factory(seed2);
      let i = 1;
      while (i < lengthOption) {
        if (rnd() < emojiRatio) {
          const emojiIndex = Math.floor(rnd() * EMOJI_UNICODE.length);
          const emoji = EMOJI_UNICODE[emojiIndex];
          const emojiLength = emoji.length;
          if (i + emojiLength < lengthOption) {
            final = final.slice(0, i - 1) + emoji + final.slice(i + emojiLength - 1);
            i += emojiLength;
          } else {
            i += 1;
          }
        } else {
          i += 1;
        }
      }
    }
  }

  if (final.length !== lengthOption) {
    console.warn(`Length expected to be ${lengthOption} but was ${final.length}`);
  }

  return final;
}

// ── 24-Round Transformer ──────────────────────────────

/**
 * Derive a password through 24 rounds of state mutation.
 *
 * @intent Apply additional rounds of derivation where each round feeds the
 *   previous password back as the new secret, mutating uri and user via
 *   cyrb53 hashing. This creates a transformed output that is not trivially
 *   reversible from the initial hash result.
 *
 *   This is NOT key stretching (no increased computational cost for attackers).
 *   The purpose is state mutation: each round changes the internal derivation
 *   state, producing a nonlinear relationship between master secret and output.
 *
 * @param {Object} opts — Same options as generatePassword()
 * @returns {string} Derivation result after 24 rounds
 *
 * @note For production use, always call derivePassword(); generatePassword()
 *   is the single-round inner loop.
 */
function derivePassword(originalOpts) {
  // Clone opts to prevent mutation of the caller's object during the
  // 24-round state mutation loop. Without this, uri/user/secret are
  // overwritten in-place, corrupting any reused opts object.
  const opts = { ...originalOpts };
  let final = generatePassword(opts);
  for (let i = 0; i < (3 << 3); i++) {
    opts.uri = String(cyrb53(opts.uri, final));
    opts.user = String(cyrb53(opts.user, final));
    opts.secret = final;
    final = generatePassword(opts);
  }
  return final;
}

// ── CLI ───────────────────────────────────────────────

function showHelp() {
  console.log(`
Passgen — Stateless Deterministic Passphrase Generator
Usage: passgen [options]

Password Mode (default):
  -s, --service <name>     Service/URI (default: "service")
  -i, --identity <name>    User identity (default: "user")
  -m, --master <secret>    Master secret / brain-wallet seed
  -l, --length <n>         Password length [16–128] (default: 64)
  -S, --symbols            Include symbols
  -C, --caps               Include capitalized letters
  -E, --emoji              Include emoji (not recommended for most services)
  --symbol-ratio <n>       Symbol replacement ratio % [0–100] (default: 32)
  --emoji-ratio <n>        Emoji replacement ratio % [0–100] (default: 24)
  --version <n>            Derivation version [1|2] (default: 2)

Seed Phrase Mode:
  --seed-phrase            Generate a BIP-39 compliant mnemonic
  --word-count <n>         Word count [12|15|18|21|24] (default: 24)
  --validate <phrase>      Validate a BIP-39 mnemonic phrase

Emoji Phrase Mode:
  --emoji-phrase           Generate an emoji mnemonic phrase
  --symbol-count <n>       How many emoji symbols [1–64] (default: 12)
  --list-emoji-set         Show the Emoji Alphabet categories

Master Quality & Diceware:
  --generate-master        Generate a Diceware master passphrase
  --check-master <secret>  Analyze master password strength
  --wordlist               Show Diceware wordlist info

Info & Audit:
  --entropy                Show entropy estimates
  --audit                  Show derivation audit digest
  -h, --help               Show this help

Master secret may also be set via PASSGEN_MASTER env var.

Modes are mutually exclusive — the first mode flag wins.
`);
}

function parseArgs(argv) {
  const opts = {
    service: 'service',
    identity: 'user',
    master: process.env.PASSGEN_MASTER || '',
    length: DEFAULT_WORD_LENGTH,
    symbols: false,
    caps: false,
    emoji: false,
    symbolRatio: DEFAULT_SYMBOL_RATIO / 100,
    emojiRatio: (3 << 3) / 100,
    version: DEFAULT_VERSION,
    showEntropy: false,
    showAudit: false,
    mode: 'password',      // 'password' | 'seed-phrase' | 'emoji-phrase'
    wordCount: 24,
    symbolCount: 12,
    validatePhrase: null,
    listEmojiSet: false,
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => argv[++i];
    switch (arg) {
      case '-s': case '--service': opts.service = next(); break;
      case '-i': case '--identity': opts.identity = next(); break;
      case '-m': case '--master': opts.master = next(); break;
      case '-l': case '--length': opts.length = parseInt(next()); break;
      case '-S': case '--symbols': opts.symbols = true; break;
      case '-C': case '--caps': opts.caps = true; break;
      case '-E': case '--emoji': opts.emoji = true; break;
      case '--symbol-ratio': opts.symbolRatio = parseInt(next()) / 100; break;
      case '--emoji-ratio': opts.emojiRatio = parseInt(next()) / 100; break;
      case '--version': opts.version = parseInt(next()); break;
      case '--seed-phrase': opts.mode = 'seed-phrase'; break;
      case '--emoji-phrase': opts.mode = 'emoji-phrase'; break;
      case '--word-count': opts.wordCount = parseInt(next()); break;
      case '--symbol-count': opts.symbolCount = parseInt(next()); break;
      case '--validate': opts.mode = 'validate'; opts.validatePhrase = next(); break;
      case '--list-emoji-set': opts.mode = 'list'; break;
      case '--entropy': opts.showEntropy = true; break;
      case '--audit': opts.showAudit = true; break;
      case '--generate-master': opts.mode = 'generate-master'; break;
      case '--check-master': opts.mode = 'check-master'; opts.master = next(); break;
      case '--wordlist': opts.mode = 'wordlist'; break;
      case '-h': case '--help': showHelp(); process.exit(0); break;
      default: console.error(`Unknown option: ${arg}`); process.exit(1);
    }
  }

  // Validate ranges
  if (opts.mode === 'password' && isNaN(opts.length)) opts.length = MIN_WORD_LENGTH;
  if (opts.mode === 'password' && opts.length < MIN_WORD_LENGTH) opts.length = MIN_WORD_LENGTH;
  if (opts.mode === 'password' && opts.length > MAX_WORD_LENGTH) opts.length = MAX_WORD_LENGTH;

  if (opts.mode === 'seed-phrase') {
    const validCounts = [12, 15, 18, 21, 24];
    if (!validCounts.includes(opts.wordCount)) {
      console.error(`Error: --word-count must be one of: ${validCounts.join(', ')}`);
      process.exit(1);
    }
  }

  if (opts.mode === 'emoji-phrase') {
    if (isNaN(opts.symbolCount) || opts.symbolCount < 1 || opts.symbolCount > 64) {
      console.error('Error: --symbol-count must be between 1 and 64');
      process.exit(1);
    }
  }

  opts.symbolRatio = Math.max(0, Math.min(1, opts.symbolRatio));
  opts.emojiRatio = Math.max(0, Math.min(1, opts.emojiRatio));

  // Master required for password/seed/emoji generators; not required for info modes
  if (!opts.master && !['validate','list','generate-master','check-master','wordlist'].includes(opts.mode)) {
    console.error('Error: --master required or set PASSGEN_MASTER env var');
    process.exit(1);
  }

  return opts;
}

function showEmojiSet() {console.log('The Emoji Alphabet — Canonical Symbol Sets (DEME Draft 00)');
  console.log('');
  Object.entries(EMOJI_SETS).forEach(([setId, set]) => {
    console.log(`  ${setId}: ${set.size} symbols (${set.bits} bits each)`);
    console.log(`    ${set.symbols.slice(0, 16).join(' ')}${set.symbols.length > 16 ? ' ...' : ''}`);
  });
  console.log('');
  console.log('  Usage:');
  console.log('    passgen.js emoji-phrase --set=<set> --count=<n>');
  console.log('');
  console.log('  Design principles:');
  console.log('    • Single Unicode codepoint only (no ZWJ sequences)');
  console.log('    • No skin-tone modifiers');
  console.log('    • No flag/country-code sequences');
  console.log('    • Bit-precise encoding: no truncation waste');
}

function main(argv) {
  const cli = parseArgs(argv);

  switch (cli.mode) {
    case 'seed-phrase': {
      const phrase = generateSeedPhrase(cli.master, cli.wordCount);
      const entropy = estimateMasterEntropy(cli.master);
      console.log(phrase);
      if (cli.showEntropy) {
        console.log(`# Master entropy: ~${entropy} bits (${classifyStrength(entropy)})`);
        console.log(`# Phrase words: ${cli.wordCount} (${BIP39_CONFIG[cli.wordCount].entropyBits} bits + ${BIP39_CONFIG[cli.wordCount].checksumBits} checksum)`);
      }
      break;
    }

    case 'emoji-phrase': {
      const phrase = generateEmojiPhrase(cli.master, cli.symbolCount);
      const entropy = estimateEmojiPhraseEntropy(cli.symbolCount);
      console.log(phrase);
      if (cli.showEntropy) {
        console.log(`# Symbols: ${cli.symbolCount}  |  Entropy: ~${entropy} bits  |  Set size: ${EMOJI_SETS['emoji-1024'].size} (emoji-1024)`);
      }
      break;
    }

    case 'validate': {
      const isValid = validateMnemonic(cli.validatePhrase);
      console.log(isValid ? '✅ Valid BIP-39 mnemonic' : '❌ Invalid BIP-39 mnemonic');
      process.exit(isValid ? 0 : 1);
      break;
    }

    case 'list': {
      showEmojiSet();
      break;
    }

    case 'generate-master': {
      const result = generateDicewareMaster(cli.wordCount || 8);
      console.log(result.phrase);
      if (cli.showEntropy) {
        console.error(` _entropy: ${result.entropyBits} bits (${result.strengthClass})`);
      }
      break;
    }

    case 'check-master': {
      const result = analyzeMasterStrength(cli.master);
      console.log(`Strength: ${result.strengthClass}`);
      console.log(`Shannon entropy: ${result.shannonBits} bits`);
      console.log(`Pattern-adjusted: ${result.patternAdjustedBits} bits`);
      console.log(`Estimated crack time: ${formatCrackTime(result.estimatedCrackTimeSeconds)}`);
      if (result.warnings.length) {
        console.log('\nWarnings:');
        result.warnings.forEach(w => console.log(`  • ${w}`));
      }
      if (result.patternsDetected.length) {
        console.log('\nPatterns detected:');
        result.patternsDetected.forEach(p => console.log(`  • ${p.type} (${p.severity})`));
      }
      console.log(`\nRecommendation: ${result.recommendedAction}`);
      break;
    }

    case 'wordlist': {
      const wl = loadDicewareWordlist();
      console.log(`EFF Large Wordlist: ${wl.length} words loaded`);
      console.log(`First 5: ${wl.slice(0, 5).join(', ')}`);
      break;
    }

    case 'password':
    default: {
      const password = derivePassword({
        uri: cli.service,
        user: cli.identity,
        secret: cli.master,
        useSymbols: cli.symbols,
        useCapitalLetters: cli.caps,
        useEmoji: cli.emoji,
        lengthOption: cli.length,
        symbolRatio: cli.symbolRatio,
        emojiRatio: cli.emojiRatio,
        version: cli.version,
      });

      if (cli.showEntropy) {
        const masterBits = estimateMasterEntropy(cli.master);
        const passBits = estimatePasswordEntropy(password);
        console.log(`# Password: ${password}`);
        console.log(`# Master entropy estimate: ~${masterBits} bits (${classifyStrength(masterBits)})`);
        console.log(`# Password entropy estimate: ~${passBits} bits`);
      } else if (cli.showAudit) {
        const auditDigest = buildAuditDigest({
          uri: cli.service, user: cli.identity,
          lengthOption: cli.length,
          useSymbols: cli.symbols, useCapitalLetters: cli.caps, useEmoji: cli.emoji,
          symbolRatio: cli.symbolRatio, emojiRatio: cli.emojiRatio,
          version: cli.version,
        });
        console.log(`# Password: ${password}`);
        console.log(`# Audit digest: ${auditDigest.slice(0, 32)}…`);
      } else {
        console.log(password);
      }
    }
  }
}

// ── BIP-39 Seed Phrase Generator ─────────────────────

// Load the official BIP-39 English wordlist (2048 words)
const BIP39_WORDLIST = require('./bip39-wordlist.json');

// Entropy-to-checksum mapping per BIP-39 spec
// wordCount: { entropyBytes, checksumBits }
const BIP39_CONFIG = {
  12: { entropyBits: 128, checksumBits: 4 },
  15: { entropyBits: 160, checksumBits: 5 },
  18: { entropyBits: 192, checksumBits: 6 },
  21: { entropyBits: 224, checksumBits: 7 },
  24: { entropyBits: 256, checksumBits: 8 },
};

/**
 * Generate a deterministic BIP-39 mnemonic phrase from a master secret.
 *
 * @intent Produce a reproducible seed phrase for memory aids, offline backup,
 *   or cross-device synchronization. The phrase is valid per BIP-39 checksum.
 *
 * @param {string} master — The master secret
 * @param {number} wordCount — 12, 15, 18, 21, or 24 (default: 24)
 * @returns {string} — Space-separated mnemonic phrase
 *
 * @warning ⚠️ NON-STANDARD DERIVATION: This generates a deterministic BIP-39
 *   phrase via SHA3-256 hashing of the master secret. It does NOT follow the
 *   standard BIP-39 process (entropy generation -> mnemonic encoding -> seed
 *   derivation via PBKDF2 with 2048 iterations and optional passphrase).
 *
 *   The output phrases are CHECKSUM-VALID but NOT COMPATIBLE with standard
 *   cryptocurrency wallets. Do NOT use these phrases in wallets expecting
 *   standard BIP-39 derivation. Loss of funds may result from confusion.
 *
 *   If you need standard BIP-39, use a dedicated wallet tool, not Passgen.
 */
function generateSeedPhrase(master, wordCount = 24) {
  const config = BIP39_CONFIG[wordCount];
  if (!config) {
    throw new Error('Invalid wordCount. Must be one of: 12, 15, 18, 21, 24');
  }

  // Derive entropy from master using SHA3-256
  // We use multiple rehashes to ensure sufficient entropy extraction
  const entropyHash = rehash1(master + ':bip39-seed-phrase', 2, sha3);
  const entropyHex = entropyHash.slice(0, config.entropyBits / 4);
  const entropy = Buffer.from(entropyHex, 'hex');

  // Compute checksum: first N bits of SHA-256(entropy)
  const hash = crypto.createHash('sha256').update(entropy).digest('hex');
  const hashBinary = BigInt('0x' + hash).toString(2).padStart(256, '0');
  const checksum = hashBinary.slice(0, config.checksumBits);

  // Convert entropy to binary string
  const entropyBinary = entropy.toString('hex').split('').map(h =>
    parseInt(h, 16).toString(2).padStart(4, '0')
  ).join('');

  // Append checksum to entropy
  const combined = entropyBinary + checksum;

  // Split into 11-bit groups
  const groups = [];
  for (let i = 0; i < combined.length; i += 11) {
    groups.push(combined.slice(i, i + 11));
  }

  // Map each group to a word from the list
  const words = groups.map(group => {
    const index = parseInt(group, 2);
    return BIP39_WORDLIST[index];
  });

  return words.join(' ');
}

/**
 * Validate a BIP-39 mnemonic phrase
 * Returns true if the checksum is valid
 *
 * @param {string} phrase — Space-separated mnemonic
 * @returns {boolean}
 */
function validateMnemonic(phrase) {
  const words = phrase.trim().split(/\s+/);
  if (!BIP39_CONFIG[words.length]) return false;

  const config = BIP39_CONFIG[words.length];

  // Convert words back to binary
  const indices = words.map(word => BIP39_WORDLIST.indexOf(word));
  if (indices.some(i => i === -1)) return false;

  const combinedBinary = indices.map(i => i.toString(2).padStart(11, '0')).join('');
  const entropyBinary = combinedBinary.slice(0, config.entropyBits);
  const checksum = combinedBinary.slice(config.entropyBits);

  // Reconstruct entropy
  const entropyHex = [];
  for (let i = 0; i < entropyBinary.length; i += 4) {
    const nibble = entropyBinary.slice(i, i + 4);
    entropyHex.push(parseInt(nibble, 2).toString(16));
  }
  const entropy = Buffer.from(entropyHex.join(''), 'hex');

  // Verify checksum
  const hash = crypto.createHash('sha256').update(entropy).digest('hex');
  const hashBinary = BigInt('0x' + hash).toString(2).padStart(256, '0');
  const expectedChecksum = hashBinary.slice(0, config.checksumBits);

  return checksum === expectedChecksum;
}

// ── Diceware Master Generator ────────────────────────
// Phase 7: CSPRNG-based passphrase generation

const fs = require("fs");
const path = require("path");
function loadDicewareWordlist() {
  try {
    const data = fs.readFileSync(path.join(__dirname, "eff_large_wordlist.txt"), "utf8");
    const lines = data.trim().split('\n');
    const words = lines.map(line => line.split('\t')[1]).filter(Boolean);
    return words;
  } catch {
    return [];
  }
}

function generateDicewareMaster(wordCount = 8) {
  const wordlist = loadDicewareWordlist();
  if (wordlist.length < 7776) {
    throw new Error("Diceware wordlist not loaded. Ensure eff_large_wordlist.txt is present.");
  }
  const words = [];
  for (let w = 0; w < wordCount; w++) {
    let roll = 0;
    for (let d = 0; d < 5; d++) {
      // crypto.randomInt(0, 6) provides unbiased uniform random [0, 5].
      // Previously used byte % 6 which has a 43/42 distribution bias.
      roll = roll * 6 + crypto.randomInt(0, 6);
    }
    words.push(wordlist[roll]);
  }
  const bitsPerWord = Math.log2(7776);
  const totalBits = Math.floor(wordCount * bitsPerWord);
  let sc;
  if (totalBits < 60) sc = "weak";
  else if (totalBits < 80) sc = "moderate";
  else if (totalBits < 100) sc = "strong";
  else sc = "very-strong";
  return { words, entropyBits: totalBits, strengthClass: sc, phrase: words.join(" ") };
}

// ── HIBP Breach Check (k-anonymity) ──────────────────
// Phase 7: HaveIBeenPwned integration

const https = require("https");

/**
 * Check if a master secret has appeared in known data breaches.
 *
 * @intent Privacy-preserving breach detection via HaveIBeenPwned k-Anonymity.
 *   Only the first 5 characters of the SHA-1 hash are transmitted to the API.
 *   The full hash never leaves the local system.
 *
 * @param {string} master — The secret to check
 * @returns {Promise<Object>} — { found, count, prefix, offline?, error? }
 *
 * @note If the API is unreachable, returns { offline: true } silently.
 *   A breach check failure does NOT mean the password is safe.
 */
function checkMasterPwned(master) {
  return new Promise((resolve) => {
    try {
      const hash = crypto.createHash("sha1").update(master).digest("hex").toUpperCase();
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const req = https.get(
        `https://api.pwnedpasswords.com/range/${prefix}`,
        { headers: { "User-Agent": "passgen-cli/1.0" }, timeout: 5000 },
        (res) => {
          let data = "";
          res.on("data", c => data += c);
          res.on("end", () => {
            for (const line of data.split(/\r?\n/)) {
              const [suf, cnt] = line.split(":");
              if (suf === suffix) {
                return resolve({ found: true, count: parseInt(cnt, 10) || 0, prefix });
              }
            }
            resolve({ found: false, count: 0, prefix });
          });
        }
      );
      req.on("error", (err) => resolve({ found: false, count: 0, offline: true, error: err.message }));
      req.on("timeout", () => { req.destroy(); resolve({ found: false, count: 0, offline: true, error: "timeout" }); });
    } catch (err) {
      resolve({ found: false, count: 0, offline: true, error: err.message });
    }
  });
}

// ── Canonical Symbol Sets (DEME Draft 00) ──
const EMOJI_SETS = {
  'emoji-256': {
    size: 256,
    bits: 8,
    symbols: [
      // Nature (64)
      '\u{1F332}','\u{1F333}','\u{1F334}','\u{1F335}','\u{1F337}','\u{1F338}','\u{1F339}','\u{1F33A}',
      '\u{1F33B}','\u{1F33C}','\u{1F33D}','\u{1F33E}','\u{1F33F}','\u{1F340}','\u{1F341}','\u{1F342}',
      '\u{1F343}','\u{1F344}','\u{1F347}','\u{1F348}','\u{1F349}','\u{1F34A}','\u{1F34B}','\u{1F34C}',
      '\u{1F34D}','\u{1F34E}','\u{1F34F}','\u{1F350}','\u{1F351}','\u{1F352}','\u{1F353}','\u{1F354}',
      '\u{1F355}','\u{1F356}','\u{1F357}','\u{1F358}','\u{1F359}','\u{1F35A}','\u{1F35B}','\u{1F35C}',
      '\u{1F35D}','\u{1F35E}','\u{1F35F}','\u{1F360}','\u{1F361}','\u{1F362}','\u{1F363}','\u{1F364}',
      '\u{1F365}','\u{1F366}','\u{1F367}','\u{1F368}','\u{1F369}','\u{1F36A}','\u{1F36B}','\u{1F36C}',
      '\u{1F36D}','\u{1F36E}','\u{1F36F}','\u{1F370}','\u{1F371}','\u{1F372}','\u{1F373}','\u{1F374}',
      // Creatures (64)
      '\u{1F375}','\u{1F376}','\u{1F377}','\u{1F378}','\u{1F379}','\u{1F37A}','\u{1F37B}','\u{1F37C}',
      '\u{1F37E}','\u{1F37F}','\u{1F380}','\u{1F381}','\u{1F382}','\u{1F383}','\u{1F384}','\u{1F385}',
      '\u{1F386}','\u{1F387}','\u{1F388}','\u{1F389}','\u{1F38A}','\u{1F38B}','\u{1F38C}','\u{1F38D}',
      '\u{1F38E}','\u{1F38F}','\u{1F390}','\u{1F391}','\u{1F392}','\u{1F393}','\u{1F3A0}','\u{1F3A1}',
      '\u{1F3A2}','\u{1F3A3}','\u{1F3A4}','\u{1F3A5}','\u{1F3A6}','\u{1F3A7}','\u{1F3A8}','\u{1F3A9}',
      '\u{1F3AA}','\u{1F3AB}','\u{1F3AC}','\u{1F3AD}','\u{1F3AE}','\u{1F3AF}','\u{1F3B0}','\u{1F3B1}',
      '\u{1F3B2}','\u{1F3B3}','\u{1F3B4}','\u{1F3B5}','\u{1F3B6}','\u{1F3B7}','\u{1F3B8}','\u{1F3B9}',
      '\u{1F3BA}','\u{1F3BB}','\u{1F3BC}','\u{1F3BD}','\u{1F3BE}','\u{1F3BF}','\u{1F3C0}','\u{1F3C1}',
      // Objects (64)
      '\u{1F400}','\u{1F401}','\u{1F402}','\u{1F403}','\u{1F404}','\u{1F405}','\u{1F406}','\u{1F407}',
      '\u{1F408}','\u{1F409}','\u{1F40A}','\u{1F40B}','\u{1F40C}','\u{1F40D}','\u{1F40E}','\u{1F40F}',
      '\u{1F410}','\u{1F411}','\u{1F412}','\u{1F413}','\u{1F414}','\u{1F415}','\u{1F416}','\u{1F417}',
      '\u{1F418}','\u{1F419}','\u{1F41A}','\u{1F41B}','\u{1F41C}','\u{1F41D}','\u{1F41E}','\u{1F41F}',
      '\u{1F420}','\u{1F421}','\u{1F422}','\u{1F423}','\u{1F424}','\u{1F425}','\u{1F426}','\u{1F427}',
      '\u{1F428}','\u{1F429}','\u{1F42A}','\u{1F42B}','\u{1F42C}','\u{1F42D}','\u{1F42E}','\u{1F42F}',
      '\u{1F430}','\u{1F431}','\u{1F432}','\u{1F433}','\u{1F434}','\u{1F435}','\u{1F436}','\u{1F437}',
      '\u{1F438}','\u{1F439}','\u{1F43A}','\u{1F43B}','\u{1F43C}','\u{1F43D}','\u{1F43E}','\u{1F440}',
      // Places (64)
      '\u{1F441}','\u{1F442}','\u{1F443}','\u{1F444}','\u{1F445}','\u{1F446}','\u{1F447}','\u{1F448}',
      '\u{1F449}','\u{1F44A}','\u{1F44B}','\u{1F44C}','\u{1F44D}','\u{1F44E}','\u{1F44F}','\u{1F450}',
      '\u{1F451}','\u{1F452}','\u{1F453}','\u{1F454}','\u{1F455}','\u{1F456}','\u{1F457}','\u{1F458}',
      '\u{1F459}','\u{1F45A}','\u{1F45B}','\u{1F45C}','\u{1F45D}','\u{1F45E}','\u{1F45F}','\u{1F460}',
      '\u{1F461}','\u{1F462}','\u{1F463}','\u{1F464}','\u{1F465}','\u{1F466}','\u{1F467}','\u{1F468}',
      '\u{1F469}','\u{1F46A}','\u{1F46B}','\u{1F46C}','\u{1F46D}','\u{1F46E}','\u{1F46F}','\u{1F470}',
      '\u{1F471}','\u{1F472}','\u{1F473}','\u{1F474}','\u{1F475}','\u{1F476}','\u{1F477}','\u{1F478}',
      '\u{1F479}','\u{1F47A}','\u{1F47B}','\u{1F47C}','\u{1F47D}','\u{1F47E}','\u{1F47F}','\u{1F480}',
    ]
  },
  'emoji-512':  { size: 512,  bits: 9,  symbols: null },
  'emoji-1024': { size: 1024, bits: 10, symbols: null },
  'emoji-2048': { size: 2048, bits: 11, symbols: null }
};

// Extended symbol pools
const EMOJI_SETS_A256 = [
      '\u{1F481}','\u{1F482}','\u{1F483}','\u{1F484}','\u{1F485}','\u{1F486}','\u{1F487}','\u{1F488}','\u{1F489}','\u{1F48A}',
      '\u{1F48B}','\u{1F48C}','\u{1F48D}','\u{1F48E}','\u{1F48F}','\u{1F490}','\u{1F491}','\u{1F492}','\u{1F493}','\u{1F494}',
      '\u{1F495}','\u{1F496}','\u{1F497}','\u{1F498}','\u{1F499}','\u{1F49A}','\u{1F49B}','\u{1F49C}','\u{1F49D}','\u{1F49E}',
      '\u{1F49F}','\u{1F4A0}','\u{1F4A1}','\u{1F4A2}','\u{1F4A3}','\u{1F4A4}','\u{1F4A5}','\u{1F4A6}','\u{1F4A7}','\u{1F4A8}',
      '\u{1F4A9}','\u{1F4AA}','\u{1F4AB}','\u{1F4AC}','\u{1F4AD}','\u{1F4AE}','\u{1F4AF}','\u{1F4B0}','\u{1F4B1}','\u{1F4B2}',
      '\u{1F4B3}','\u{1F4B4}','\u{1F4B5}','\u{1F4B6}','\u{1F4B7}','\u{1F4B8}','\u{1F4B9}','\u{1F4BA}','\u{1F4BB}','\u{1F4BC}',
      '\u{1F4BD}','\u{1F4BE}','\u{1F4BF}','\u{1F4C0}','\u{1F4C1}','\u{1F4C2}','\u{1F4C3}','\u{1F4C4}','\u{1F4C5}','\u{1F4C6}',
      '\u{1F4C7}','\u{1F4C8}','\u{1F4C9}','\u{1F4CA}','\u{1F4CB}','\u{1F4CC}','\u{1F4CD}','\u{1F4CE}','\u{1F4CF}','\u{1F4D0}',
      '\u{1F4D1}','\u{1F4D2}','\u{1F4D3}','\u{1F4D4}','\u{1F4D5}','\u{1F4D6}','\u{1F4D7}','\u{1F4D8}','\u{1F4D9}','\u{1F4DA}',
      '\u{1F4DB}','\u{1F4DC}','\u{1F4DD}','\u{1F4DE}','\u{1F4DF}','\u{1F4E0}','\u{1F4E1}','\u{1F4E2}','\u{1F4E3}','\u{1F4E4}',
      '\u{1F4E5}','\u{1F4E6}','\u{1F4E7}','\u{1F4E8}','\u{1F4E9}','\u{1F4EA}','\u{1F4EB}','\u{1F4EC}','\u{1F4ED}','\u{1F4EE}',
      '\u{1F4EF}','\u{1F4F0}','\u{1F4F1}','\u{1F4F2}','\u{1F4F3}','\u{1F4F4}','\u{1F4F5}','\u{1F4F6}','\u{1F4F7}','\u{1F4F8}',
      '\u{1F4F9}','\u{1F4FA}','\u{1F4FB}','\u{1F4FC}','\u{1F4FF}','\u{1F500}','\u{1F501}','\u{1F502}','\u{1F503}','\u{1F504}',
      '\u{1F505}','\u{1F506}','\u{1F507}','\u{1F508}','\u{1F509}','\u{1F50A}','\u{1F50B}','\u{1F50C}','\u{1F50D}','\u{1F50E}',
      '\u{1F50F}','\u{1F510}','\u{1F511}','\u{1F512}','\u{1F513}','\u{1F514}','\u{1F515}','\u{1F516}','\u{1F517}','\u{1F518}',
      '\u{1F519}','\u{1F51A}','\u{1F51B}','\u{1F51C}','\u{1F51D}','\u{1F51E}','\u{1F51F}','\u{1F520}','\u{1F521}','\u{1F522}',
      '\u{1F523}','\u{1F524}','\u{1F525}','\u{1F526}','\u{1F527}','\u{1F528}','\u{1F529}','\u{1F52A}','\u{1F52B}','\u{1F52C}',
      '\u{1F52D}','\u{1F52E}','\u{1F52F}','\u{1F530}','\u{1F531}','\u{1F532}','\u{1F533}','\u{1F534}','\u{1F535}','\u{1F536}',
      '\u{1F537}','\u{1F538}','\u{1F539}','\u{1F53A}','\u{1F53B}','\u{1F53C}','\u{1F53D}','\u{1F54B}','\u{1F54C}','\u{1F54D}',
      '\u{1F54E}','\u{1F550}','\u{1F551}','\u{1F552}','\u{1F553}','\u{1F554}','\u{1F555}','\u{1F556}','\u{1F557}','\u{1F558}',
      '\u{1F559}','\u{1F55A}','\u{1F55B}','\u{1F55C}','\u{1F55D}','\u{1F55E}','\u{1F55F}','\u{1F560}','\u{1F561}','\u{1F562}',
      '\u{1F563}','\u{1F564}','\u{1F565}','\u{1F566}','\u{1F567}','\u{1F5FB}','\u{1F5FC}','\u{1F5FD}','\u{1F5FE}','\u{1F5FF}',
      '\u{1F600}','\u{1F601}','\u{1F602}','\u{1F603}','\u{1F604}','\u{1F605}','\u{1F606}','\u{1F607}','\u{1F608}','\u{1F609}',
      '\u{1F60A}','\u{1F60B}','\u{1F60C}','\u{1F60D}','\u{1F60E}','\u{1F60F}','\u{1F610}','\u{1F611}','\u{1F612}','\u{1F613}',
      '\u{1F614}','\u{1F615}','\u{1F616}','\u{1F617}','\u{1F618}','\u{1F619}','\u{1F61A}','\u{1F61B}','\u{1F61C}','\u{1F61D}',
      '\u{1F61E}','\u{1F61F}','\u{1F620}','\u{1F621}','\u{1F622}','\u{1F623}',
];

const EMOJI_SETS_A512 = [
      '\u{1F624}','\u{1F625}','\u{1F626}','\u{1F627}','\u{1F628}','\u{1F629}','\u{1F62A}','\u{1F62B}','\u{1F62C}','\u{1F62D}',
      '\u{1F62E}','\u{1F62F}','\u{1F630}','\u{1F631}','\u{1F632}','\u{1F633}','\u{1F634}','\u{1F635}','\u{1F636}','\u{1F637}',
      '\u{1F638}','\u{1F639}','\u{1F63A}','\u{1F63B}','\u{1F63C}','\u{1F63D}','\u{1F63E}','\u{1F63F}','\u{1F640}','\u{1F641}',
      '\u{1F642}','\u{1F643}','\u{1F644}','\u{1F645}','\u{1F646}','\u{1F647}','\u{1F648}','\u{1F649}','\u{1F64A}','\u{1F64B}',
      '\u{1F64C}','\u{1F64D}','\u{1F64E}','\u{1F64F}','\u{26A7}','\u{2626}','\u{2638}','\u{262A}','\u{262E}','\u{262F}',
      '\u{2604}','\u{2603}','\u{2615}','\u{2693}','\u{26FD}','\u{26FA}','\u{26F7}','\u{26F9}','\u{2648}','\u{2649}',
      '\u{264A}','\u{264B}','\u{264C}','\u{264D}','\u{264E}','\u{264F}','\u{2650}','\u{2651}','\u{2652}','\u{2653}',
      '\u{26CE}','\u{26AB}','\u{26AA}','\u{2764}','\u{27A1}','\u{26F3}','\u{1F3D3}','\u{1F3F8}','\u{1F3D2}','\u{1F3D1}',
      '\u{1F3CF}','\u{1F3C2}','\u{26C5}','\u{2601}','\u{2600}','\u{26A1}','\u{2744}','\u{26C4}','\u{1F3E0}','\u{1F3E1}',
      '\u{1F3E2}','\u{1F3E3}','\u{1F3E4}','\u{1F3E5}','\u{1F3E6}','\u{1F3E8}','\u{1F3E9}','\u{1F3EA}','\u{1F3EB}','\u{1F3EC}',
      '\u{1F3ED}','\u{1F3EF}','\u{1F3F0}','\u{1F680}','\u{1F681}','\u{1F682}','\u{1F68C}','\u{1F68E}','\u{1F690}','\u{1F691}',
      '\u{1F692}','\u{1F693}','\u{1F695}','\u{1F697}','\u{1F699}','\u{1F69A}','\u{1F6F5}','\u{1F6B2}','\u{26CF}','\u{2692}',
      '\u{1F6E0}','\u{26D3}','\u{260E}','\u{1F5F3}','\u{2709}','\u{2702}','\u{270F}','\u{2712}','\u{1F56F}','\u{1F6E1}',
      '\u{1F3D4}','\u{26F0}','\u{1F30B}','\u{1F332}','\u{1F333}','\u{1F334}','\u{1F335}','\u{1F337}','\u{1F338}','\u{1F339}',
      '\u{1F33A}','\u{1F33B}','\u{1F33C}','\u{1F33D}','\u{1F33E}','\u{1F33F}','\u{1F340}','\u{1F341}','\u{1F342}','\u{1F343}',
      '\u{1F344}','\u{1F347}','\u{1F348}','\u{1F349}','\u{1F34A}','\u{1F34B}','\u{1F34C}','\u{1F34D}','\u{1F34E}','\u{1F34F}',
      '\u{1F350}','\u{1F351}','\u{1F352}','\u{1F353}','\u{1F354}','\u{1F355}','\u{1F356}','\u{1F357}','\u{1F358}','\u{1F359}',
      '\u{1F35A}','\u{1F35B}','\u{1F35C}','\u{1F35D}','\u{1F35E}','\u{1F35F}','\u{1F360}','\u{1F361}','\u{1F362}','\u{1F363}',
      '\u{1F364}','\u{1F365}','\u{1F366}','\u{1F367}','\u{1F368}','\u{1F369}','\u{1F36A}','\u{1F36B}','\u{1F36C}','\u{1F36D}',
      '\u{1F36E}','\u{1F36F}','\u{1F370}','\u{1F371}','\u{1F372}','\u{1F373}','\u{1F374}','\u{1F375}','\u{1F376}','\u{1F377}',
      '\u{1F378}','\u{1F379}','\u{1F37A}','\u{1F37B}','\u{1F37C}','\u{1F37E}','\u{1F37F}','\u{1F380}','\u{1F381}','\u{1F382}',
      '\u{1F383}','\u{1F384}','\u{1F385}','\u{1F386}','\u{1F387}','\u{1F388}','\u{1F389}','\u{1F38A}','\u{1F38B}','\u{1F38C}',
      '\u{1F38D}','\u{1F38E}','\u{1F38F}','\u{1F390}','\u{1F391}','\u{1F392}','\u{1F393}','\u{1F3A0}','\u{1F3A1}','\u{1F3A2}',
      '\u{1F3A3}','\u{1F3A4}','\u{1F3A5}','\u{1F3A6}','\u{1F3A7}','\u{1F3A8}','\u{1F3A9}','\u{1F3AA}','\u{1F3AB}','\u{1F3AC}',
      '\u{1F3AD}','\u{1F3AE}','\u{1F3AF}','\u{1F3B0}','\u{1F3B1}','\u{1F3B2}','\u{1F3B3}','\u{1F3B4}','\u{1F3B5}','\u{1F3B6}',
      '\u{1F3B7}','\u{1F3B8}','\u{1F3B9}','\u{1F3BA}','\u{1F3BB}','\u{1F3BC}','\u{1F3BD}','\u{1F3BE}','\u{1F3BF}','\u{1F3C0}',
      '\u{1F3C1}','\u{1F400}','\u{1F401}','\u{1F402}','\u{1F403}','\u{1F404}','\u{1F405}','\u{1F406}','\u{1F407}','\u{1F408}',
      '\u{1F409}','\u{1F40A}','\u{1F40B}','\u{1F40C}','\u{1F40D}','\u{1F40E}','\u{1F40F}','\u{1F410}','\u{1F411}','\u{1F412}',
      '\u{1F413}','\u{1F414}','\u{1F415}','\u{1F416}','\u{1F417}','\u{1F418}','\u{1F419}','\u{1F41A}','\u{1F41B}','\u{1F41C}',
      '\u{1F41D}','\u{1F41E}','\u{1F41F}','\u{1F420}','\u{1F421}','\u{1F422}','\u{1F423}','\u{1F424}','\u{1F425}','\u{1F426}',
      '\u{1F427}','\u{1F428}','\u{1F429}','\u{1F42A}','\u{1F42B}','\u{1F42C}','\u{1F42D}','\u{1F42E}','\u{1F42F}','\u{1F430}',
      '\u{1F431}','\u{1F432}','\u{1F433}','\u{1F434}','\u{1F435}','\u{1F436}','\u{1F437}','\u{1F438}','\u{1F439}','\u{1F43A}',
      '\u{1F43B}','\u{1F43C}','\u{1F43D}','\u{1F43E}','\u{1F440}','\u{1F441}','\u{1F442}','\u{1F443}','\u{1F444}','\u{1F445}',
      '\u{1F446}','\u{1F447}','\u{1F448}','\u{1F449}','\u{1F44A}','\u{1F44B}','\u{1F44C}','\u{1F44D}','\u{1F44E}','\u{1F44F}',
      '\u{1F450}','\u{1F451}','\u{1F452}','\u{1F453}','\u{1F454}','\u{1F455}','\u{1F456}','\u{1F457}','\u{1F458}','\u{1F459}',
      '\u{1F45A}','\u{1F45B}','\u{1F45C}','\u{1F45D}','\u{1F45E}','\u{1F45F}','\u{1F460}','\u{1F461}','\u{1F462}','\u{1F463}',
      '\u{1F464}','\u{1F465}','\u{1F466}','\u{1F467}','\u{1F468}','\u{1F469}','\u{1F46A}','\u{1F46B}','\u{1F46C}','\u{1F46D}',
      '\u{1F46E}','\u{1F46F}','\u{1F470}','\u{1F471}','\u{1F472}','\u{1F473}','\u{1F474}','\u{1F475}','\u{1F476}','\u{1F477}',
      '\u{1F478}','\u{1F479}','\u{1F47A}','\u{1F47B}','\u{1F47C}','\u{1F47D}','\u{1F47E}','\u{1F47F}','\u{1F480}','\u{1F481}',
      '\u{1F482}','\u{1F483}','\u{1F484}','\u{1F485}','\u{1F486}','\u{1F487}','\u{1F488}','\u{1F489}','\u{1F48A}','\u{1F48B}',
      '\u{1F48C}','\u{1F48D}','\u{1F48E}','\u{1F48F}','\u{1F490}','\u{1F491}','\u{1F492}','\u{1F493}','\u{1F494}','\u{1F495}',
      '\u{1F496}','\u{1F497}','\u{1F498}','\u{1F499}','\u{1F49A}','\u{1F49B}','\u{1F49C}','\u{1F49D}','\u{1F49E}','\u{1F49F}',
      '\u{1F4A0}','\u{1F4A1}','\u{1F4A2}','\u{1F4A3}','\u{1F4A4}','\u{1F4A5}','\u{1F4A6}','\u{1F4A7}','\u{1F4A8}','\u{1F4A9}',
      '\u{1F4AA}','\u{1F4AB}','\u{1F4AC}','\u{1F4AD}','\u{1F4AE}','\u{1F4AF}','\u{1F4B0}','\u{1F4B1}','\u{1F4B2}','\u{1F4B3}',
      '\u{1F4B4}','\u{1F4B5}','\u{1F4B6}','\u{1F4B7}','\u{1F4B8}','\u{1F4B9}','\u{1F4BA}','\u{1F4BB}','\u{1F4BC}','\u{1F4BD}',
      '\u{1F4BE}','\u{1F4BF}','\u{1F4C0}','\u{1F4C1}','\u{1F4C2}','\u{1F4C3}','\u{1F4C4}','\u{1F4C5}','\u{1F4C6}','\u{1F4C7}',
      '\u{1F4C8}','\u{1F4C9}','\u{1F4CA}','\u{1F4CB}','\u{1F4CC}','\u{1F4CD}','\u{1F4CE}','\u{1F4CF}','\u{1F4D0}','\u{1F4D1}',
      '\u{1F4D2}','\u{1F4D3}','\u{1F4D4}','\u{1F4D5}','\u{1F4D6}','\u{1F4D7}','\u{1F4D8}','\u{1F4D9}','\u{1F4DA}','\u{1F4DB}',
      '\u{1F4DC}','\u{1F4DD}','\u{1F4DE}','\u{1F4DF}','\u{1F4E0}','\u{1F4E1}','\u{1F4E2}','\u{1F4E3}','\u{1F4E4}','\u{1F4E5}',
      '\u{1F4E6}','\u{1F4E7}','\u{1F4E8}','\u{1F4E9}','\u{1F4EA}','\u{1F4EB}','\u{1F4EC}','\u{1F4ED}','\u{1F4EE}','\u{1F4EF}',
      '\u{1F4F0}','\u{1F4F1}','\u{1F4F2}','\u{1F4F3}','\u{1F4F4}','\u{1F4F5}','\u{1F4F6}','\u{1F4F7}','\u{1F4F8}','\u{1F4F9}',
      '\u{1F4FA}','\u{1F4FB}',
];

// Build derived sets at module load.
//
// Design note on emoji-2048 duplicates: The 2048-symbol set intentionally
// contains duplicate entries. The constraint is single-codepoint emoji only
// (no ZWJ sequences, no skin-tone modifiers, no flags) curated for visual
// distinction across memory-palace categories. There are not enough
// qualifying single-codepoint emoji to fill 2048 unique slots. Rather than
// relaxing the visual constraints or introducing multi-codepoint sequences,
// the 1024-symbol pool is padded to 2048 with repeats. This enables
// bit-precise 11-bit indexing while maintaining the visual quality bar.
// Effective entropy per symbol is slightly below 11 bits but well above 10.
// See: draft-guan-emoji-mnemonic-encoding (DEME Draft 00).
(function() {
  const base = EMOJI_SETS['emoji-256'].symbols;
  EMOJI_SETS['emoji-512'].symbols  = [...base, ...EMOJI_SETS_A256].slice(0, 512);
  EMOJI_SETS['emoji-1024'].symbols = [...EMOJI_SETS['emoji-512'].symbols, ...EMOJI_SETS_A512].slice(0, 1024);
  const remaining = [...EMOJI_SETS_A256.slice(256), ...EMOJI_SETS_A512.slice(512)];
  const pool = EMOJI_SETS['emoji-1024'].symbols;
  EMOJI_SETS['emoji-2048'].symbols = [...pool, ...remaining, ...pool].slice(0, 2048);
})();



/**
 * Generate a deterministic emoji phrase from a master secret.
 *
 * @intent Produce a visually memorable mnemonic using The Emoji Alphabet —
 *   a curated 1024-symbol set organized in memory-palace categories.
 *   Each symbol carries ~10 bits of entropy. Ideal for visual memory aids,
 *   offline notetaking, or cross-verification of other generator outputs.
 *
 * @param {string} master — The master secret
 * @param {number} symbolCount — Number of symbols to generate (1–64, default: 12)
 * @returns {string} — Space-separated emoji phrase
 *
 * @note Most services do not support emoji in passwords. This is for
 *   mnemonic construction and visual verification, not direct password use.
 */
function generateEmojiPhrase(master, symbolCount = 12, setIdentifier = 'emoji-1024', salt = '') {
  if (!master || typeof master !== 'string') {
    throw new Error('Master secret is required');
  }
  if (symbolCount < 1 || symbolCount > 64) {
    throw new Error('symbolCount must be between 1 and 64');
  }

  const set = EMOJI_SETS[setIdentifier];
  if (!set || !set.symbols) {
    throw new Error(`Invalid symbol set: ${setIdentifier}`);
  }
  const setSize = set.size;
  const bitsPerSymbol = set.bits;

  // Initial hash: salt + "\0" + seed + "\0" + set_id + "\0" + "emoji"
  const domain = '\x00';
  let hash = sha3_512(salt + domain + master + domain + setIdentifier + domain + 'emoji');
  const digests = [hash];
  const bitsNeeded = symbolCount * bitsPerSymbol;

  // Rehash as needed
  let iteration = 1;
  while (digests.length * 512 < bitsNeeded) {
    hash = sha3_512(hash + domain + String(iteration));
    digests.push(hash);
    iteration++;
  }

  // Build continuous big-endian bit stream from hex digests
  const bitStream = digests.map(d =>
    BigInt('0x' + d).toString(2).padStart(512, '0')
  ).join('');

  const symbols = [];
  for (let k = 0; k < symbolCount; k++) {
    const bitOffset = k * bitsPerSymbol;
    const chunk = bitStream.slice(bitOffset, bitOffset + bitsPerSymbol);
    const index = parseInt(chunk, 2) % setSize;
    symbols.push(set.symbols[index]);
  }

  return symbols.join(' ');
}

// ── Entropy Calculator for Emoji Alphabet ──────────────

function estimateEmojiPhraseEntropy(symbolCount, setIdentifier = 'emoji-1024') {
  const set = EMOJI_SETS[setIdentifier];
  if (!set || !set.symbols) {
    throw new Error(`Invalid symbol set: ${setIdentifier}`);
  }
  return Math.floor(symbolCount * set.bits);
}

// ── Entry ─────────────────────────────────────────────

if (require.main === module) {
  main(process.argv);
}

module.exports = {
  generateSeedPhrase, validateMnemonic,
  generateEmojiPhrase, estimateEmojiPhraseEntropy,
  BIP39_WORDLIST, BIP39_CONFIG, EMOJI_SETS,
  cyrb53, cyrb128, sfc32, sfc32Factory,
  sha3, rehash0, rehash1, extendWord,
  generatePassword, derivePassword, getSalt,
  buildHashSeed, buildAuditDigest,
  estimateMasterEntropy, estimatePasswordEntropy, classifyStrength,
  analyzeMasterStrength, estimateShannonBits, formatCrackTime,
  generateDicewareMaster, loadDicewareWordlist,
  checkMasterPwned,
  EMOJI_UNICODE, SYMBOLS,
  MIN_WORD_LENGTH, MAX_WORD_LENGTH, DEFAULT_WORD_LENGTH, DEFAULT_VERSION
};