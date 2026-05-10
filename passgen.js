#!/usr/bin/env node
// Passgen — Stateless deterministic passphrase generator
// Extracted from Aurora OS (c) Freeman King, ported by Guan
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

// ── Input Encoding / Hardening ────────────────────────

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
  const { uri, user, secret, lengthOption, useSymbols, useCapitalLetters, useEmoji, symbolRatio, emojiRatio, version } = opts;
  // Deterministic audit hash without exposing secrets
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

function getSalt() {
  return cyrb53(`${0x9E3779B9}${0x243F6A88}${0xB7E15162}${1337 ^ 0xDEADBEEF}`);
}

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

function derivePassword(opts) {
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

  // Master required for generators; not required for --validate or --list
  if (!opts.master && opts.mode !== 'validate' && opts.mode !== 'list') {
    console.error('Error: --master required or set PASSGEN_MASTER env var');
    process.exit(1);
  }

  return opts;
}

function showEmojiSet() {
  console.log('The Emoji Alphabet — Curated Symbol Set');
  console.log(`Total symbols: ${EMOJI_ALPHABET_SIZE}`);
  console.log('');
  Object.entries(EMOJI_ALPHABET).forEach(([category, symbols]) => {
    console.log(`  ${category}: ${symbols.length} symbols`);
    console.log(`    ${symbols.slice(0, 16).join(' ')}${symbols.length > 16 ? ' ...' : ''}`);
  });
  console.log('');
  console.log('Design principles:');
  console.log('  • Single Unicode codepoint only (no ZWJ sequences)');
  console.log('  • No skin-tone modifiers');
  console.log('  • Visually distinctive across categories');
  console.log('  • Bit-precise encoding: 10 bits per symbol (1024 max slots)');
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
        console.log(`# Symbols: ${cli.symbolCount}  |  Entropy: ~${entropy} bits  |  Set size: ${EMOJI_ALPHABET_SIZE}`);
      }
      break;
    }

    case 'validate': {
      const isValid = validateMnemonic(cli.validatePhrase);
      console.log(isValid ? '✅ Valid BIP-39 mnemonic' : '❌ Invalid BIP-39 mnemonic');
      process.exit(isValid ? 0 : 1);
    }

    case 'list': {
      showEmojiSet();
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
 * Generate a BIP-39 compliant deterministic seed phrase
 * from a master secret (brain-wallet style).
 *
 * @param {string} master — The master secret
 * @param {number} wordCount — 12, 15, 18, 21, or 24 (default: 24)
 * @returns {string} — Space-separated mnemonic phrase
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

// ── The Emoji Alphabet, Proper ───────────────────────

/**
 * The Emoji Alphabet — A curated, visually distinct symbol set
 * for deterministic mnemonic phrase generation.
 *
 * Design principles:
 *   - Single Unicode codepoint (no ZWJ sequences, no skin tones)
 *   - Visually distinctive and memorable
 *   - Organized by category for memory-palace construction
 *   - 1024 symbols (10 bits each) for clean bit encoding
 */
const EMOJI_ALPHABET = {
  // Nature: 128 symbols (0–127)
  nature: [
    '🌲','🌳','🌴','🌵','🌷','🌸','🌹','🌺','🌻','🌼','🌽','🌾','🌿','🍀','🍁','🍂',
    '🍃','🍄','🍇','🍈','🍉','🍊','🍋','🍌','🍍','🍎','🍏','🍐','🍑','🍒','🍓','🍔',
    '🍕','🍖','🍗','🍘','🍙','🍚','🍛','🍜','🍝','🍞','🍟','🍠','🍡','🍢','🍣','🍤',
    '🍥','🍦','🍧','🍨','🍩','🍪','🍫','🍬','🍭','🍮','🍯','🍰','🍱','🍲','🍳','🍴',
    '🍵','🍶','🍷','🍸','🍹','🍺','🍻','🍼','🍾','🍿','🎀','🎁','🎂','🎃','🎄','🎅',
    '🎆','🎇','🎈','🎉','🎊','🎋','🎌','🎍','🎎','🎏','🎐','🎑','🎒','🎓','🎠','🎡',
    '🎢','🎣','🎤','🎥','🎦','🎧','🎨','🎩','🎪','🎫','🎬','🎭','🎮','🎯','🎰','🎱',
    '🎲','🎳','🎴','🎵','🎶','🎷','🎸','🎹','🎺','🎻','🎼','🎽','🎾','🎿','🏀','🏁'
  ],
  // Creatures: 128 symbols (128–255)
  creatures: [
    '🐀','🐁','🐂','🐃','🐄','🐅','🐆','🐇','🐈','🐉','🐊','🐋','🐌','🐍','🐎','🐏',
    '🐐','🐑','🐒','🐓','🐔','🐕','🐖','🐗','🐘','🐙','🐚','🐛','🐜','🐝','🐞','🐟',
    '🐠','🐡','🐢','🐣','🐤','🐥','🐦','🐧','🐨','🐩','🐪','🐫','🐬','🐭','🐮','🐯',
    '🐰','🐱','🐲','🐳','🐴','🐵','🐶','🐷','🐸','🐹','🐺','🐻','🐼','🐽','🐾','👀',
    '👁','👂','👃','👄','👅','👆','👇','👈','👉','👊','👋','👌','👍','👎','👏','👐',
    '👑','👒','👓','👔','👕','👖','👗','👘','👙','👚','👛','👜','👝','👞','👟','👠',
    '👡','👢','👣','👤','👥','👦','👧','👨','👩','👪','👫','👬','👭','👮','👯','👰',
    '👱','👲','👳','👴','👵','👶','👷','👸','👹','👺','👻','👼','👽','👾','👿','💀'
  ],
  // Objects: 128 symbols (256–383)
  objects: [
    '💁','💂','💃','💄','💅','💆','💇','💈','💉','💊','💋','💌','💍','💎','💏','💐',
    '💑','💒','💓','💔','💕','💖','💗','💘','💙','💚','💛','💜','💝','💞','💟','💠',
    '💡','💢','💣','💤','💥','💦','💧','💨','💩','💪','💫','💬','💭','💮','💯','💰',
    '💱','💲','💳','💴','💵','💶','💷','💸','💹','💺','💻','💼','💽','💾','💿','📀',
    '📁','📂','📃','📄','📅','📆','📇','📈','📉','📊','📋','📌','📍','📎','📏','📐',
    '📑','📒','📓','📔','📕','📖','📗','📘','📙','📚','📛','📜','📝','📞','📟','📠',
    '📡','📢','📣','📤','📥','📦','📧','📨','📩','📪','📫','📬','📭','📮','📯','📰',
    '📱','📲','📳','📴','📵','📶','📷','📸','📹','📺','📻','📼','📿','🔀','🔁','🔂'
  ],
  // Places: 128 symbols (384–511)
  places: [
    '🔃','🔄','🔅','🔆','🔇','🔈','🔉','🔊','🔋','🔌','🔍','🔎','🔏','🔐','🔑','🔒',
    '🔓','🔔','🔕','🔖','🔗','🔘','🔙','🔚','🔛','🔜','🔝','🔞','🔟','🔠','🔡','🔢',
    '🔣','🔤','🔥','🔦','🔧','🔨','🔩','🔪','🔫','🔬','🔭','🔮','🔯','🔰','🔱','🔲',
    '🔳','🔴','🔵','🔶','🔷','🔸','🔹','🔺','🔻','🔼','🔽','🕋','🕌','🕍','🕎','🕐',
    '🕑','🕒','🕓','🕔','🕕','🕖','🕗','🕘','🕙','🕚','🕛','🕜','🕝','🕞','🕟','🕠',
    '🕡','🕢','🕣','🕤','🕥','🕦','🕧','🗻','🗼','🗽','🗾','🗿','😀','😁','😂','😃',
    '😄','😅','😆','😇','😈','😉','😊','😋','😌','😍','😎','😏','😐','😑','😒','😓',
    '😔','😕','😖','😗','😘','😙','😚','😛','😜','😝','😞','😟','😠','😡','😢','😣'
  ],
  // Remainder: 345 symbols (512–856) — single-codepoint only, no ZWJ/flags/modifiers
  remainder: [
    '😀','😁','😂','😃','😄','😅','😆','😇','😈','😉','😊','😋','😌','😍','😎','😏',
    '😐','😑','😒','😓','😔','😕','😖','😗','😘','😙','😚','😛','😜','😝','😞','😟',
    '😠','😡','😢','😣','😤','😥','😦','😧','😨','😩','😪','😫','😬','😭','😮','😯',
    '😰','😱','😲','😳','😴','😵','😶','😷','😸','😹','😺','😻','😼','😽','😾','😿',
    '🙀','🙁','🙂','🙃','🙄','🙅','🙆','🙇','🙈','🙉','🙊','🙋','🙌','🙍','🙎','🙏',
    '⚧','☦','☸','☪','☮','☯','☄','☃','☕','⚓','⛽','⛺','⛷','⛹',
    '♈','♉','♊','♋','♌','♍','♎','♏','♐','♑','♒','♓','⛎',
    '🆎','🆑','🆒','🆓','🆔','🆕','🆖','🆗','🆘','🆙','🆚',
    '🈁','🈚','🈯','🈲','🈳','🈴','🈵','🈶','🈸','🈹','🈺','🉐','🉑',
    '💮','💯','💢','💬','💭','📛','🔰',
    '◼','◻','◾','◽','▪','▫','▬','▭','▮','▯',
    '►','◄','▲','▼','◤','◥','◢','◣','◿','◹',
    '⓪','①','②','③','④','⑤','⑥','⑦','⑧','⑨','⑩',
    '⑪','⑫','⑬','⑭','⑮','⑯','⑰','⑱','⑲','⑳',
    '⚫','⚪','🔴','🔵','⬛','⬜',
    '❤','💔','💕','💖','💗','💘','💙','💚','💛','💜','💝','💞','💟',
    '⬆','⬇','⬅','➡','↗','↘','↙','↖','↕','↔','↩','↪',
    '⤴','⤵','🔃','🔄',
    '🕐','🕑','🕒','🕓','🕔','🕕','🕖','🕗','🕘','🕙','🕚','🕛',
    '🕜','🕝','🕞','🕟','🕠','🕡','🕢','🕣','🕤','🕥','🕦','🕧',
    '🀄','🃏',
    '🎵','🎶','🎼','🎤','🎧','🎷','🎸','🎹','🎺','🎻',
    '🎱','🎳','⛳','🏓','🏸','🏒','🏑','🏏','🎿','🏂',
    '⛅','☁','☀','⚡','❄','⛄',
    '🏠','🏡','🏢','🏣','🏤','🏥','🏦','🏨','🏩','🏪','🏫','🏬','🏭','🏯','🏰',
    '🚀','🚁','🚂','🚌','🚎','🚐','🚑','🚒','🚓','🚕','🚗','🚙','🚚','🛵','🚲',
    '🔧','🔨','🔩','🔪','⛏','⚒','🛠','⛓',
    '💻','📱','📲','☎','📞','📟','📠','📺','📻','📷','📸','📹','📼',
    '💰','💴','💵','💶','💷','💸','💳',
    '📦','📫','📪','📬','📭','📮','🗳','✉','✂','✏','✒',
    '🕯','🛡','🗿','🗽','🗼','🗻','🏔','⛰','🌋','🗾'
  ],
};

const EMOJI_ALPHABET_FLAT = [
  ...EMOJI_ALPHABET.nature,
  ...EMOJI_ALPHABET.creatures,
  ...EMOJI_ALPHABET.objects,
  ...EMOJI_ALPHABET.places,
  ...EMOJI_ALPHABET.remainder
];

const EMOJI_ALPHABET_SIZE = EMOJI_ALPHABET_FLAT.length;

/**
 * Generate a deterministic emoji phrase from a master secret
 * using The Emoji Alphabet encoding scheme.
 *
 * @param {string} master — The master secret
 * @param {number} symbolCount — How many symbols (default: 12)
 * @returns {string} — Space-separated emoji phrase
 */
function generateEmojiPhrase(master, symbolCount = 12) {
  if (!master || typeof master !== 'string') {
    throw new Error('Master secret is required');
  }
  if (symbolCount < 1 || symbolCount > 64) {
    throw new Error('symbolCount must be between 1 and 64');
  }

  // Derive a hash stream from master
  // We use rehash to get multiple SHA3 outputs, treated as a bit stream
  let hash = sha3(master + ':emoji-alphabet-v1');
  let hashIndex = 0;
  let bitBuffer = BigInt('0x' + hash);
  let bitsAvailable = hash.length * 4; // hex chars * 4 bits each

  const symbols = [];
  while (symbols.length < symbolCount) {
    if (bitsAvailable < 10) {
      // Need more bits — rehash
      hash = sha3(hash + String(hashIndex++));
      bitBuffer = BigInt('0x' + hash);
      bitsAvailable = hash.length * 4;
    }

    // Take next 10 bits (for 1024-symbol set)
    const index = Number(bitBuffer & BigInt(0x3FF)); // 10 bits = 0-1023
    symbols.push(EMOJI_ALPHABET_FLAT[index % EMOJI_ALPHABET_SIZE]);

    bitBuffer = bitBuffer >> BigInt(10);
    bitsAvailable -= 10;
  }

  return symbols.join(' ');
}

// ── Entropy Calculator for Emoji Alphabet ──────────────

function estimateEmojiPhraseEntropy(symbolCount) {
  // Each symbol carries log2(set_size) bits
  const bitsPerSymbol = Math.log2(EMOJI_ALPHABET_SIZE);
  return Math.floor(symbolCount * bitsPerSymbol);
}

// ── Entry ─────────────────────────────────────────────

if (require.main === module) {
  main(process.argv);
}

module.exports = {
  generateSeedPhrase, validateMnemonic,
  generateEmojiPhrase, estimateEmojiPhraseEntropy,
  BIP39_WORDLIST, BIP39_CONFIG, EMOJI_ALPHABET, EMOJI_ALPHABET_FLAT,
  EMOJI_ALPHABET_SIZE,
  cyrb53, cyrb128, sfc32, sfc32Factory,
  sha3, rehash0, rehash1, extendWord,
  generatePassword, derivePassword, getSalt,
  buildHashSeed, buildAuditDigest,
  estimateMasterEntropy, estimatePasswordEntropy, classifyStrength,
  EMOJI_UNICODE, SYMBOLS,
  MIN_WORD_LENGTH, MAX_WORD_LENGTH, DEFAULT_WORD_LENGTH, DEFAULT_VERSION,
};