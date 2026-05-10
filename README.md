# Passgen

> Stateless deterministic passphrase generator — extracted from Aurora OS  
> License: MIT | Node.js ≥ 20

---

## Table of Contents

| Section | Audience |
|---------|----------|
| [What & Why](#what--why) | Everyone |
| [Quick Start](#quick-start) | End users, developers |
| [Security Architecture](#security-architecture) | Security engineers, auditors |
| [Generator Types](#generator-types) | Everyone |
| [Entropy & Analysis](#entropy--analysis) | Security engineers |
| [MCP Integration](#mcp-integration) | Agent developers |
| [CLI Reference](#cli-reference) | End users |
| [API Reference](#api-reference) | Library consumers |
| [Security Considerations](#security-considerations) | Everyone |
| [Changelog](#changelog) | Maintainers |

---

## What & Why

Passgen derives passwords, seed phrases, and mnemonics from **one master secret**.

No database. No vault. No file to lose. Your master secret is a brain-wallet seed — everything else is deterministic.

Same inputs always produce the same outputs. Different services always produce different outputs. This is guaranteed by cryptographic namespace hardening and null-delimited encoding.

### Why stateless?

- **No sync required** — works offline on any device
- **No backup needed** — the master secret IS the backup
- **Auditability** — every output is reproducible from first principles
- **Transparency** — all code is inspectable; no proprietary algorithm

### Historical context

Passgen was extracted from **Aurora OS**, a research operating system for agentic AI infrastructure. The original implementation was embedded in the OS boot chain. This standalone package preserves the same derivation logic for broader use.

---

## Quick Start

### Install

```bash
npm install -g passgen
# or locally
npm install passgen
```

### Generate a password

```bash
# CLI
passgen -s github.com -i personal -m "your-master-secret-here"
# → cJ9$kL2mP@vQxR5t... (64 chars)

# Via env (avoids shell history)
PASSGEN_MASTER="your-secret" passgen -s github.com -i personal
```

### Generate a BIP-39 seed phrase

```bash
passgen --seed-phrase -m "your-master-secret"
# → abandon ability able about above absent absorb abstract absurd ...
```

### Generate an emoji mnemonic

```bash
passgen --emoji-phrase --symbol-count 12 -m "your-master-secret"
# → 🎸 🍉 👑 🌵 💡 🐊 🍁 🏠 💎 🎪 🔑 🌙
```

### Library usage

```javascript
const { derivePassword, generateSeedPhrase, analyzeMasterStrength } = require('passgen');

const password = derivePassword({
  uri: 'github.com',
  user: 'personal',
  secret: 'your-master-secret',
  lengthOption: 32,
  useSymbols: true,
  version: 2
});

const phrase = generateSeedPhrase('your-master-secret', 24);

const analysis = analyzeMasterStrength('my-password-123!');
console.log(analysis.strengthClass); // "weak"
```

---

## Security Architecture

### Derivation pipeline

```
master + service + identity
        ↓
    buildHashSeed()
    (null-delimited encoding)
        ↓
    SHA3-256 (rehash × 16)
        ↓
    BigInt → base36 string
        ↓
    derivePassword() — 24 additional rounds
        ↓
    Optional: symbols, caps, emoji (PRNG placement)
        ↓
    final password
```

### Version 1 vs Version 2

| | Version 1 | Version 2 (default) |
|---|---|---|
| **Encoding** | Bare concatenation: `uri+user+secret+salt` | Null-delimited: `\turi\0user\0secret\0salt` |
| **Collision risk** | Service `('ba', 'nk')` collides with `('b', 'ank')` | Unambiguous boundary parsing |
| **Use** | Backward compatibility with Aurora OS outputs | All new installations |

Version 2 prevents **dangling-suffix attacks** where attackers exploit ambiguous concatenation to produce identical hashes from different credential triples.

### 24-round transformer

After the initial hash, `derivePassword()` performs **24 additional rounds**:
- Each round: `uri = hash(uri)`, `user = hash(user)`, `secret = previous_password`
- Result fed back into `generatePassword()`

This is **not** PBKDF2 or bcrypt. The purpose is not key stretching (that happens from the entropy of the master secret). The purpose is **state mutation**: each round changes the internal state derived from the master, producing a transformed output that cannot be trivially reversed from the initial hash.

### Salt

The salt is **not random**. It is a deterministic constant derived from a fixed sequence:

```js
getSalt() = cyrb53(`${0x9E3779B9}${0x243F6A88}${0xB7E15162}${1337 ^ 0xDEADBEEF}`)
```

This is intentional. A stateless system cannot store per-user salts. The fixed salt provides:
- **Determinism**: same inputs → same outputs across all devices
- **No database**: nothing to store, nothing to leak

The security model assumes the master secret has sufficient entropy to resist pre-computation attacks independent of salting.

### PRNG placement

Symbols, capitals, and emoji are placed using `sfc32`, a PractRand-passing PRNG seeded from `cyrb128` of the intermediate hash. The placement is deterministic for the same derivation path.

---

## Generator Types

### Password Generator (default)

```bash
passgen -s <service> -i <identity> -m <master> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --service` | `"service"` | Service name or URI |
| `-i, --identity` | `"user"` | User identity or account |
| `-m, --master` | `PASSGEN_MASTER` | Master secret (env preferred) |
| `-l, --length` | `64` | Password length (16–128) |
| `-S, --symbols` | `false` | Include `~!@#$%^&*()...` |
| `-C, --caps` | `false` | Include uppercase letters |
| `-E, --emoji` | `false` | Include emoji (service compatibility: poor) |
| `--symbol-ratio` | `32` | `%` of chars replaced with symbols |
| `--emoji-ratio` | `24` | `%` of chars replaced with emoji |
| `--version` | `2` | Derivation version (1 = legacy) |

### BIP-39 Seed Phrase

```bash
passgen --seed-phrase -m <master> [--word-count 12|15|18|21|24]
```

Generates a **deterministic BIP-39 mnemonic** from the master secret.

⚠️ **NON-STANDARD DERIVATION**: Passgen derives entropy via `SHA3-256(master + ':bip39-seed-phrase')` and maps it to BIP-39 word indices with proper checksum. This is NOT the standard BIP-39 process (PBKDF2, 2048 iterations, optional passphrase). Do NOT use this seed phrase in cryptocurrency wallets expecting standard derivation. The phrase is reproducible and valid per BIP-39 checksum, but the entropy path is different.

### Emoji Alphabet Phrase

```bash
passgen --emoji-phrase -m <master> [--symbol-count N]
```

Uses **The Emoji Alphabet** — a curated set of **1024 visually distinct single-codepoint symbols** organized into memory-palace categories (`nature`, `creatures`, `objects`, `places`, `remainder`).

Each symbol carries **~10 bits** of entropy. A 12-symbol phrase = ~120 bits.

Design constraints:
- Single Unicode codepoint only (no ZWJ sequences like 👨‍👩‍👧)
- No skin-tone modifiers
- Visually distinctive across categories
- Bit-precise: 10 bits select from 1024 slots

### Diceware Passphrase

```bash
passgen --generate-master [--word-count 6–10]
```

Uses the **EFF Large Wordlist** (7776 words) with CSPRNG dice rolls. Each word = ~12.9 bits.

⚠️ This generator uses `crypto.randomBytes()` — not deterministic from a master secret. For deterministic Diceware-style output, use the password generator with `length=32` and no symbols.

---

## Entropy & Analysis

### Honest entropy estimation

Passgen performs **pattern-adjusted entropy analysis** on master secrets:

```bash
passgen --check-master "MyP@ssw0rd123"
```

Output:
```
Strength: weak
Shannon entropy: 72 bits
Pattern-adjusted: 32 bits
Estimated crack time: ~4 seconds
Warnings:
  • Contains common password: "password"
  • Sequential digits: "123"
Patterns detected:
  • dictionary-word (critical)
  • sequential-digits (high)
Recommendation: Use a longer passphrase or Diceware.
```

#### Detection patterns:

| Pattern | Severity | Detection method |
|---------|----------|----------------|
| Dictionary word | Critical | 50-word weak-password set + substitution unmasking (`@→a`, `$→s`, `1→i`, etc.) |
| Keyboard walk | High | 20+ known sequences (`qwerty`, `1qaz2wsx`, etc.) |
| Sequential digits | High | 3+ digits with +1 progression |
| Repeated digits | High | 3+ identical digits |
| Repeated characters | Medium | 3+ identical chars |
| Substitution mask | High | Unmasked form matches dictionary |

#### Crack time estimation:

Assumes **1 trillion guesses/second** (consumer GPUs) with slowdown factor from `PASSGEN_ROUNDS` env var (default 24). Formula:

```
crackTime = (2^patternAdjustedBits / 1e12) × (rounds / 24)
```

This is **conservative** — real attackers may use:
- Custom wordlists (smaller effective search space)
- Rule-based mutations (Markov chains, keyboard adjacency)
- ASICs or botnets (higher guesses/second)

The estimate is a lower bound, not a guarantee.

### Master entropy vs password entropy

| Input | Estimation method | Purpose |
|-------|-----------------|---------|
| Master secret | Character-class based: `log2(charsetSize) × length` | Check if master is strong enough |
| Generated password | Shannon entropy via character frequency | Quantify final output strength |
| Emoji phrase | `symbolCount × log2(1024)` | Theoretical maximum from symbol set |

---

## MCP Integration

Passgen exposes **9 tools** via the Model Context Protocol (MCP).

### Transport modes

```bash
# stdio (for agent integration)
./mcp-server.mjs --stdio

# HTTP
./mcp-server.mjs --http

# SSE
./mcp-server.mjs --sse

# Via env
PASSGEN_MCP_TRANSPORT=sse ./mcp-server.mjs
```

### Tools exposed

| Tool | Purpose | Returns |
|------|---------|---------|
| `generate_password` | Derive password from master+service+identity | Password string |
| `analyze_master_strength` | Deep pattern detection + crack time | Structured analysis |
| `check_entropy` | Quick entropy estimate (legacy) | Bit count + classification |
| `audit_params` | Deterministic digest of derivation params | SHA3 hash for cross-device comparison |
| `generate_seed_phrase` | BIP-39 mnemonic | Word phrase |
| `generate_emoji_phrase` | Emoji Alphabet mnemonic | Emoji string |
| `generate_diceware_passphrase` | CSPRNG Diceware | Word phrase |
| `check_master_breach` | HaveIBeenPwned k-Anonymity check | Breach status + count |
| `get_diceware_wordlist_info` | Wordlist metadata | Count + sample |

### Install as MCP server

Add to your MCP config:

```json
{
  "mcpServers": {
    "passgen": {
      "command": "node",
      "args": ["/path/to/mcp-server.mjs", "--stdio"]
    }
  }
}
```

---

## CLI Reference

### Modes

Modes are **mutually exclusive** — the first mode flag wins:

| Flag | Description |
|------|-------------|
| *(none)* | Password generation (default mode) |
| `--seed-phrase` | BIP-39 mnemonic |
| `--emoji-phrase` | Emoji Alphabet phrase |
| `--validate <phrase>` | Validate BIP-39 checksum |
| `--generate-master` | Diceware passphrase |
| `--check-master <secret>` | Analyze strength |
| `--list-emoji-set` | Show Emoji Alphabet categories |
| `--wordlist` | Show Diceware wordlist info |

### Info flags (combine with any mode)

| Flag | Description |
|------|-------------|
| `--entropy` | Show entropy estimates |
| `--audit` | Show derivation audit digest |

---

## API Reference

### Core derivation

```js
const {
  derivePassword,
  generatePassword,
  buildHashSeed,
} = require('passgen');
```

#### `derivePassword(opts)`

24-round password derivation. **Use this for production.**

```js
derivePassword({
  uri: 'github.com',
  user: 'personal',
  secret: 'master-secret',
  lengthOption: 64,
  useSymbols: false,
  useCapitalLetters: false,
  useEmoji: false,
  symbolRatio: 0.32,
  emojiRatio: 0.24,
  version: 2,
})
// → string
```

#### `generatePassword(opts)`

Single-round password generation. For internal use; prefer `derivePassword()`.

#### `buildHashSeed({ uri, user, secret, version })`

Returns the pre-hash seed string. `version: 1` = bare concatenation; `version: 2` = null-delimited.

### Seed phrase

```js
const { generateSeedPhrase, validateMnemonic } = require('passgen');

generateSeedPhrase('master', 24);  // → string (space-separated words)
validateMnemonic('abandon ability ...'); // → boolean
```

### Emoji

```js
const {
  generateEmojiPhrase,
  estimateEmojiPhraseEntropy,
  EMOJI_ALPHABET,
  EMOJI_ALPHABET_SIZE,
} = require('passgen');

generateEmojiPhrase('master', 12);     // → string
estimateEmojiPhraseEntropy(12);         // → ~120
EMOJI_ALPHABET.nature.length;           // → 128
```

### Analysis

```js
const {
  analyzeMasterStrength,
  estimateMasterEntropy,
  estimatePasswordEntropy,
  checkMasterPwned,
  formatCrackTime,
} = require('passgen');

analyzeMasterStrength('password123');
// → { shannonBits, patternAdjustedBits, estimatedCrackTimeSeconds, strengthClass, patternsDetected, warnings, recommendedAction }

checkMasterPwned('password123');
// → Promise<{ found, count, prefix }>
```

### Diceware

```js
const {
  generateDicewareMaster,
  loadDicewareWordlist,
} = require('passgen');

generateDicewareMaster(8);
// → { words, entropyBits, strengthClass, phrase }
```

---

## Security Considerations

### ⚠️ Master secret is everything

If your master secret is compromised, **ALL derived passwords are compromised**. There is no second factor, no recovery mechanism, no key rotation at the derivation layer.

Best practices:
- Use a **high-entropy master** (Diceware 8+ words, 80+ bits)
- Store the master in a hardware token or password manager
- Do NOT reuse the master secret as the password for any service
- Do NOT transmit the master secret to untrusted services

### ⚠️ Fixed salt

The salt is deterministic and public. This is a design constraint of statelessness. Security comes from master entropy, not salt secrecy.

### ⚠️ BIP-39 non-standard derivation

The seed phrase generator produces **deterministic, checksum-valid BIP-39 phrases** from a master secret. It does NOT follow the standard BIP-39 process (entropy → mnemonic → seed via PBKDF2). Do NOT use these phrases in cryptocurrency wallets.

### ⚠️ HaveIBeenPwned limitation

The breach check uses k-Anonymity (first 5 chars of SHA-1 hash). This is privacy-preserving but not zero-knowledge. The API receives your hash prefix.

If the API is unreachable, the check silently returns `offline: true`. **A breach check failure does not mean the password is safe.**

### ⚠️ Emoji compatibility

Most services do not support emoji in passwords. The emoji generator is intended for:
- Mnemonic construction (memory aids)
- Visual verification ("does this emoji phrase match my expected output?")
- Offline notetaking

Using emoji passwords on services that truncate or reject non-ASCII characters will produce **different stored passwords than expected**.

### ⚠️ Entropy estimates are lower bounds

Pattern-adjusted entropy accounts for dictionary words, keyboard walks, and sequential digits. It does NOT account for:
- Personal information (names, birthdates, pet names)
- Cultural patterns (song lyrics, quotes, keyboard layouts other than QWERTY)
- Targeted attacks (adversaries who know your interests)

The estimates assume random guessing. Real attackers use **smarter strategies**.

---

## Changelog

| Phase | Date | Description |
|-------|------|-------------|
| Phase 1 | — | Extraction from Aurora OS, core password generator |
| Phase 2 | — | Security hardening: delimiters, entropy audit, version param, namespace hardening |
| Phase 3 | — | MCP server integration: stdio/http/sse transport, 9 tools |
| Phase 4 | — | Aligned schema: Zod validation, canonical parameter names |
| Phase 5 | — | Tool naming: unified PascalCase tool names |
| Phase 6 | — | Configuration management: centralized config, per-tool defaults |
| Phase 7 | — | Security modeling: pattern detection, crack-time estimation, HIBP integration, Diceware, Emoji Alphabet |

---

## License

MIT — the maintainer King & Guan
