#!/usr/bin/env node
// Passgen — Stateless deterministic passphrase generator
// Extracted from Aurora OS (c) Freeman King, ported by Guan
// License: MIT

const crypto = require('crypto');

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

// Default symbol dictionary (excludes space and single-quote to avoid quoting issues)
const SYMBOLS = '~!@#$%^&*()_+{}|:"<>?`-=[]\\;,./';

// ── Constants ─────────────────────────────────────────

const MIN_WORD_LENGTH = 2 << 3;      // 16
const MAX_WORD_LENGTH = 2 << 6;      // 128
const DEFAULT_WORD_LENGTH = 2 << 5;  // 64

const DEFAULT_SYMBOL_RATIO = 2 << 4;  // 32

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
    symbolRatio, emojiRatio
  } = opts;

  const hash = rehash1(
    `${uri}${user}${secret}${getSalt()}`,
    2 << 3,  // 16 rounds
    sha3
  );

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

Options:
  -s, --service <name>     Service/URI (default: "service")
  -i, --identity <name>    User identity (default: "user")
  -m, --master <secret>    Master secret / brain-wallet seed
  -l, --length <n>         Password length [16–128] (default: 64)
  -S, --symbols            Include symbols
  -C, --caps               Include capitalized letters
  -E, --emoji              Include emoji (not recommended for most services)
  --symbol-ratio <n>       Symbol replacement ratio % [0–100] (default: 32)
  --emoji-ratio <n>        Emoji replacement ratio % [0–100] (default: 24)
  -h, --help               Show this help

Master secret may also be set via PASSGEN_MASTER env var.
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
      case '-h': case '--help': showHelp(); process.exit(0); break;
      default: console.error(`Unknown option: ${arg}`); process.exit(1);
    }
  }

  if (isNaN(opts.length) || opts.length < MIN_WORD_LENGTH) opts.length = MIN_WORD_LENGTH;
  if (opts.length > MAX_WORD_LENGTH) opts.length = MAX_WORD_LENGTH;

  opts.symbolRatio = Math.max(0, Math.min(1, opts.symbolRatio));
  opts.emojiRatio = Math.max(0, Math.min(1, opts.emojiRatio));

  if (!opts.master) {
    console.error('Error: --master required or set PASSGEN_MASTER env var');
    process.exit(1);
  }

  return opts;
}

function main(argv) {
  const cli = parseArgs(argv);

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
  });

  console.log(password);
}

// ── Entry ─────────────────────────────────────────────

if (require.main === module) {
  main(process.argv);
}

module.exports = {
  cyrb53, cyrb128, sfc32, sfc32Factory,
  sha3, rehash0, rehash1, extendWord,
  generatePassword, derivePassword, getSalt,
  EMOJI_UNICODE, SYMBOLS,
  MIN_WORD_LENGTH, MAX_WORD_LENGTH, DEFAULT_WORD_LENGTH,
};
