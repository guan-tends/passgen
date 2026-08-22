# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-08-22

### Fixed
- Remove all Aurora OS references from README, source files, and package.json
  (description, header comment, version table). Aurora OS was a browser-based
  decentralized OS experiment — passgen was never part of its boot chain.
- Replace "the maintainer King" with "David Newman" in LICENSE, package.json author,
  CHANGELOG, source file headers, and README license section.
- Correct MCP server header: "All tools are stateless and deterministic" →
  "Most tools are deterministic. Diceware uses crypto.randomInt() (CSPRNG)."

### Added
- Donations section in README with crypto wallet addresses (Solana, EVM, XRP)
- JSDoc documentation for all exported functions:
  cyrb53, cyrb128, sfc32, sfc32Factory, rehash0, rehash1, sha3, sha3_512,
  extendWord, estimateMasterEntropy, estimatePasswordEntropy, classifyStrength,
  estimateShannonBits, formatCrackTime, loadDicewareWordlist, generateDicewareMaster,
  analyzeMasterStrength, estimateEmojiPhraseEntropy
- JSDoc for MCP server utility functions: detectTransport, buildServerConfig

### Fixed
- **BREAKING**: Diceware MCP tool no longer accepts `master` parameter. The tool
  uses `crypto.randomInt()` (CSPRNG) and is NOT deterministic. Previous description
  falsely claimed determinism from master secret.
- Modulo bias in Diceware word selection: replaced `byte % 6` with `crypto.randomInt(0, 6)`
  for unbiased uniform distribution (Node 20+ idiomatic).
- `derivePassword()` no longer mutates the caller's options object. Input is cloned
  with spread operator before the 24-round state mutation loop.
- Salt derivation now uses SHA3-256 instead of cyrb53 for consistency with the
  rest of the codebase. Constants documented with provenance.

### Added
- LICENSE file (MIT, Copyright (c) 2026 David Newman & Guan)
- `files` field in package.json to control npm tarball contents
- ESLint configuration (eslint:recommended + Node.js globals)
- Prettier configuration
- CHANGELOG.md
- GitHub Actions CI workflow (node --test on push/PR, Node 20.x)
- Design decision comment on emoji-2048 duplicate symbols (intentional tradeoff)
- Documentation of salt constants (golden ratio, π, e, XOR sentinel)

### Changed
- Updated `@guan-tends/mcp-ai` from ^1.6.3-guan.0 to ^1.6.6-guan.0
- npm audit fix applied (0 vulnerabilities)

### Removed
- `.serena/` directory from git tracking (added to .gitignore)
- `dfhack-mcp/` unrelated directory from repository
- Duplicate JSDoc blocks on `generateSeedPhrase` and `generateEmojiPhrase`

## [0.2.0] - 2026-05-13

### Added
- Spec-compliant emoji encoding (DEME Draft 00): SHA3-512, null-delimited domain
  separation, canonical 4 symbol sets (256/512/1024/2048), bit-precise indexing.
- `sha3_512` primitive for emoji encoding pipeline.
- `EMOJI_SETS` with canonical set identifiers and entropy metadata.
- `showEmojiSet()` rewritten to iterate `EMOJI_SETS`.
- `estimateEmojiPhraseEntropy()` with `setIdentifier` parameter.

### Changed
- `generateEmojiPhrase()` rewritten per DEME Draft 00 specification.
- Removed `EMOJI_ALPHABET*` orphans from exports and CLI.

## [0.1.0] - 2026-05-10

### Added
- Phase 1: Core password generator extracted and documented.
- Phase 2: Security hardening — null-delimited encoding (v2), entropy audit,
  version parameter, namespace hardening.
- Phase 3: MCP server integration — stdio/http/sse transport, 9 tools.
- Phase 4: BIP-39 seed phrase generator (non-standard derivation, checksum-valid).
- Phase 5: MCP tool expansion and naming.
- Phase 7: Security modeling — pattern detection, crack-time estimation,
  HIBP breach checking, Diceware passphrase, Emoji Alphabet mnemonic.
- Comprehensive README.md with security architecture documentation.
- JSDoc intent comments on critical functions.
