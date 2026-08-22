#!/usr/bin/env node
/**
 * Passgen MCP Server
 *
 * @module passgen-mcp
 * @author David Newman & Guan
 * @license MIT
 * @version 1.0.0
 *
 * @description
 * Wraps the passgen core as an MCP-compatible tool server, exposing 9 tools
 * for integration with agentic AI systems (Claude, GPT, local LLMs via MCP).
 *
 * Transport modes: stdio (default for agents), http, sse
 * Most tools are stateless and deterministic — same inputs always produce
 * the same outputs. The Diceware passphrase generator is the exception:
 * it uses crypto.randomInt() (CSPRNG) and produces fresh output each call.
 *
 * Security model:
 *   - Master secrets are accepted as tool parameters but NEVER logged or stored
 *   - Audit digests exclude the master secret by design
 *   - k-Anonymity breach checking sends only the first 5 SHA-1 hash chars
 *
 * @phase Phase 3 — MCP Integration + Phase 7 Security Modeling
 */
import { createRequire } from 'module'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { createSimpleServer } from '@guan-tends/mcp-ai/simple-server/index.js'
import { z } from 'zod'

// Dynamic require to import the CJS passgen core
const require = createRequire(import.meta.url)
const __dirname = dirname(fileURLToPath(import.meta.url))
const passgen = require(join(__dirname, 'passgen.js'))

const {
  derivePassword,
  estimateMasterEntropy,
  estimatePasswordEntropy,
  classifyStrength,
  buildAuditDigest,
  generateSeedPhrase,
  generateEmojiPhrase,
  estimateEmojiPhraseEntropy,
  analyzeMasterStrength,
  formatCrackTime,
  loadDicewareWordlist,
  generateDicewareMaster,
  checkMasterPwned,
  BIP39_CONFIG,
  MIN_WORD_LENGTH,
  MAX_WORD_LENGTH,
  DEFAULT_WORD_LENGTH,
  DEFAULT_SYMBOL_RATIO,
  DEFAULT_VERSION,
} = passgen

// ── Transport Detection ───────────────────────────────
/**
 * detectTransport — Determine MCP transport mode from env, args, or TTY state.
 * Priority: PASSGEN_MCP_TRANSPORT env → CLI flags → TTY detection → http default.
 * @returns {'stdio'|'http'|'sse'} Transport mode
 */
function detectTransport() {
  const env = process.env.PASSGEN_MCP_TRANSPORT?.toLowerCase()
  if (env && ['stdio', 'http', 'sse'].includes(env)) return env
  const args = process.argv.slice(2)
  if (args.includes('--stdio')) return 'stdio'
  if (args.includes('--http')) return 'http'
  if (args.includes('--sse')) return 'sse'
  if (!process.stdin.isTTY && !process.stdout.isTTY) return 'stdio'
  return 'http'
}

/**
 * buildServerConfig — Construct MCP server config for the selected transport.
 * @param {'stdio'|'http'|'sse'} transport — Transport mode
 * @returns {{name: string, version: string, server: object}} Server config
 */
function buildServerConfig(transport) {
  const base = { name: 'passgen-mcp', version: '1.0.0' }
  switch (transport) {
    case 'stdio':  return { ...base, server: { connection: { type: 'cli' } } }
    case 'sse':    return { ...base, server: { connection: { type: 'sse', port: 48188 } } }
    case 'http':
    default:       return { ...base, server: { connection: { type: 'http', port: 48188 } } }
  }
}

const TRANSPORT = detectTransport()

// ── Tools ─────────────────────────────────────────────
const tools = [
  {
    name: 'generate_password',
    description: 'Derive a deterministic, cryptographically-stretched password from a master secret and service identity. Stateless: same inputs always produce the same password.',
    inputSchema: {
      master: z.string().min(1).describe('Master secret (brain-wallet seed). Keep this safe — it is the root of all derived passwords.'),
      service: z.string().min(1).default('service').describe('Service name or URI (e.g. "github.com", "mybank").'),
      identity: z.string().min(1).default('user').describe('User identity or account name (e.g. "personal", "work").'),
      length: z.number().int().min(MIN_WORD_LENGTH).max(MAX_WORD_LENGTH).default(DEFAULT_WORD_LENGTH).describe(`Password length in characters. Clamped to ${MIN_WORD_LENGTH}–${MAX_WORD_LENGTH}.`),
      symbols: z.boolean().default(false).describe('Include symbol characters (~!@#$% etc).'),
      caps: z.boolean().default(false).describe('Include capitalized letters.'),
      emoji: z.boolean().default(false).describe('Include emoji characters (NOT recommended for most services).'),
      symbolRatio: z.number().min(0).max(100).default(DEFAULT_SYMBOL_RATIO).describe('Percentage of characters to replace with symbols when --symbols is true.'),
      emojiRatio: z.number().min(0).max(100).default(24).describe('Percentage of characters to replace with emoji when --emoji is true.'),
      version: z.number().int().min(1).max(2).default(DEFAULT_VERSION).describe('Derivation version. v1=legacy bare concat (backward compat); v2=null-delimited encoding (secure, default).'),
    },
    execute: async ({ master, service, identity, length, symbols, caps, emoji, symbolRatio, emojiRatio, version }) => {
      if (!master) {
        return { content: [{ type: 'text', text: 'Error: master secret is required' }], isError: true }
      }
      try {
        const password = derivePassword({
          uri: service,
          user: identity,
          secret: master,
          lengthOption: length,
          useSymbols: symbols,
          useCapitalLetters: caps,
          useEmoji: emoji,
          symbolRatio: symbolRatio / 100,
          emojiRatio: emojiRatio / 100,
          version,
        })
        return { content: [{ type: 'text', text: password }] }
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }
      }
    },
  },

  {
    name: 'analyze_master_strength',
    description: 'Deep analysis of a master secret or password: Shannon entropy, pattern detection (dictionary words, keyboard walks, sequential digits, repeated characters, common passwords), strength classification, estimated crack time, and actionable recommendations. Phase 7 powered.',
    inputSchema: {
      secret: z.string().min(1).describe('Master secret or password to analyze deeply.'),
    },
    execute: async ({ secret }) => {
      try {
        const result = analyzeMasterStrength(secret)
        const lines = [
          `Strength: ${result.strengthClass}`,
          `Shannon entropy: ${result.shannonBits} bits`,
          `Pattern-adjusted: ${result.patternAdjustedBits} bits`,
          `Estimated crack time: ${formatCrackTime(result.estimatedCrackTimeSeconds)}`,
        ]
        if (result.warnings.length) {
          lines.push('', 'Warnings:')
          result.warnings.forEach(w => lines.push(`  • ${w}`))
        }
        if (result.patternsDetected.length) {
          lines.push('', 'Patterns detected:')
          result.patternsDetected.forEach(p => lines.push(`  • ${p.type} (${p.severity})`))
        }
        lines.push('', `Recommendation: ${result.recommendedAction}`)
        return { content: [{ type: 'text', text: lines.join('\n') }] }
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }
      }
    },
  },

  {
    name: 'check_entropy',
    description: 'Estimate the entropy (strength) of a master secret or generated password. Returns bits of entropy and a human-readable classification. Legacy tool — use analyze_master_strength for deeper analysis.',
    inputSchema: {
      master: z.string().optional().describe('Master secret to evaluate. If provided, estimates its entropy.'),
      password: z.string().optional().describe('Generated password to evaluate. If provided, estimates its Shannon entropy.'),
    },
    execute: async ({ master, password }) => {
      const lines = []
      if (master) {
        const bits = estimateMasterEntropy(master)
        lines.push(`Master secret: ~${bits} bits (${classifyStrength(bits)})`)
      }
      if (password) {
        const bits = estimatePasswordEntropy(password)
        lines.push(`Password: ~${bits} bits (${classifyStrength(bits)})`)
      }
      if (!lines.length) {
        return { content: [{ type: 'text', text: 'Provide --master or --password to estimate entropy.' }], isError: true }
      }
      return { content: [{ type: 'text', text: lines.join('\n') }] }
    },
  },

  {
    name: 'audit_params',
    description: 'Generate a deterministic audit digest of derivation parameters. Used to debug "why is my password different on another device?" The digest excludes the master secret for privacy.',
    inputSchema: {
      service: z.string().default('service').describe('Service name.'),
      identity: z.string().default('user').describe('User identity.'),
      length: z.number().int().default(DEFAULT_WORD_LENGTH).describe('Password length.'),
      symbols: z.boolean().default(false).describe('Include symbols.'),
      caps: z.boolean().default(false).describe('Include caps.'),
      emoji: z.boolean().default(false).describe('Include emoji.'),
      symbolRatio: z.number().default(DEFAULT_SYMBOL_RATIO).describe('Symbol ratio %.'),
      emojiRatio: z.number().default(24).describe('Emoji ratio %.'),
      version: z.number().int().default(DEFAULT_VERSION).describe('Derivation version.'),
    },
    execute: async (params) => {
      const digest = buildAuditDigest({
        uri: params.service,
        user: params.identity,
        secret: '', // never included
        lengthOption: params.length,
        useSymbols: params.symbols,
        useCapitalLetters: params.caps,
        useEmoji: params.emoji,
        symbolRatio: params.symbolRatio / 100,
        emojiRatio: params.emojiRatio / 100,
        version: params.version,
      })
      return { content: [{ type: 'text', text: `Audit digest: ${digest}\nCompare this with another device using identical parameters. If the digest matches, every byte of input matches (except master secret, by design).` }] }
    },
  },

  {
    name: 'generate_seed_phrase',
    description: 'Generate a deterministic BIP-39 seed phrase from a master secret. Supports 12, 15, 18, 21, or 24 words. The phrase is reproducible: same master and wordCount always produce the same mnemonic.',
    inputSchema: {
      master: z.string().min(1).describe('Master secret (brain-wallet seed). This is the root of all derived phrases — keep it safe.'),
      wordCount: z.number().int().min(12).max(24).default(24).describe('Number of words: 12, 15, 18, 21, or 24.'),
    },
    execute: async ({ master, wordCount }) => {
      if (!master) {
        return { content: [{ type: 'text', text: 'Error: master secret is required' }], isError: true }
      }
      if (!BIP39_CONFIG[wordCount]) {
        return { content: [{ type: 'text', text: `Error: wordCount must be one of ${Object.keys(BIP39_CONFIG).join(', ')}` }], isError: true }
      }
      try {
        const phrase = generateSeedPhrase(master, wordCount)
        const bits = BIP39_CONFIG[wordCount].entropyBits
        return { content: [{ type: 'text', text: `${phrase}\n\n(${wordCount} words, ~${bits} bits from wordlist, capped by master entropy)` }] }
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }
      }
    },
  },

  {
    name: 'generate_emoji_phrase',
    description: 'Generate a deterministic emoji phrase from a master secret using The Emoji Alphabet. Curated single-codepoint symbols organized in categories (nature, creatures, objects, places, remainder). Supports 1–64 symbols.',
    inputSchema: {
      master: z.string().min(1).describe('Master secret (brain-wallet seed).'),
      count: z.number().int().min(1).max(64).default(12).describe('Number of emoji symbols (1–64).'),
    },
    execute: async ({ master, count }) => {
      if (!master) {
        return { content: [{ type: 'text', text: 'Error: master secret is required' }], isError: true }
      }
      try {
        const phrase = generateEmojiPhrase(master, count)
        const bits = estimateEmojiPhraseEntropy(count)
        return { content: [{ type: 'text', text: `${phrase}\n\n(${count} symbols, ~${bits} bits theoretical)` }] }
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }
      }
    },
  },

  {
    name: 'generate_diceware_passphrase',
    description: 'Generate a Diceware passphrase using CSPRNG and the EFF 7776-word list. Each word is ~12.9 bits of entropy. Supports 6–10 words. NOT deterministic — each call produces a fresh random passphrase using crypto.randomInt(). For deterministic output, use the password generator instead.',
    inputSchema: {
      wordCount: z.number().int().min(6).max(10).default(8).describe('Number of words: 6–10 (default 8 = ~103 bits).'),
    },
    execute: async ({ wordCount }) => {
      try {
        const result = generateDicewareMaster(wordCount)
        return { content: [{ type: 'text', text: `${result.phrase}\n\n(${wordCount} words, ~${result.entropyBits} bits, ${result.strengthClass})` }] }
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }
      }
    },
  },

  {
    name: 'check_master_breach',
    description: 'Check if a master secret has appeared in known data breaches using HaveIBeenPwned k-Anonymity API. Only the first 5 chars of the SHA-1 hash are sent to the API. Privacy-preserving.',
    inputSchema: {
      master: z.string().min(1).describe('Master secret to check against breach databases.'),
    },
    execute: async ({ master }) => {
      if (!master) {
        return { content: [{ type: 'text', text: 'Error: master secret is required' }], isError: true }
      }
      try {
        const result = await checkMasterPwned(master)
        if (result.breached) {
          return { content: [{ type: 'text', text: `⚠️ BREACHED: Found ${result.count.toLocaleString()} time(s) in known data breaches. \n\nThis password is COMPROMISED. Change it immediately everywhere it is used. Never reuse this password. Beware: attackers may have already targeted accounts associated with this password.` }] }
        }
        return { content: [{ type: 'text', text: `✅ Clean: Not found in any known data breaches via HaveIBeenPwned.\n\nYour password has not appeared in their corpus of ${result.totalInCorpus?.toLocaleString() || 'over 1 billion'} known leaked passwords. This does not guarantee safety — it only means no match in the known-leak database.` }] }
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }
      }
    },
  },

  {
    name: 'get_diceware_wordlist_info',
    description: 'Get information about the EFF Large Wordlist used for Diceware passphrase generation. Returns word count and a sample of the first few words.',
    inputSchema: {},
    execute: async () => {
      try {
        const wl = loadDicewareWordlist()
        return { content: [{ type: 'text', text: `EFF Large Wordlist: ${wl.length} words loaded\nFirst 10: ${wl.slice(0, 10).join(', ')}\n\nEach word = ~12.9 bits of entropy.\n8 words = ~103 bits (very-strong).\n10 words = ~129 bits (cryptographic).` }] }
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }
      }
    },
  },
]

// ── Server Startup ────────────────────────────────────
// Guard: only start server when run directly (isMain), not during dynamic import
const __ENTRY_PATH = import.meta.url ? new URL(import.meta.url).pathname : ''
const isMain = process.argv[1] && (__ENTRY_PATH.endsWith(process.argv[1]) || process.argv[1].endsWith('mcp-server.mjs'))

let server = null
if (isMain) {
  console.log(`[Passgen MCP] Transport: ${TRANSPORT}`)
  const serverConfig = buildServerConfig(TRANSPORT)
  serverConfig.tools = tools
  server = createSimpleServer(serverConfig)
  await server.start()
  console.log(`[Passgen MCP] Ready — ${tools.length} tools loaded`)
  console.log(`[Passgen MCP] Tools: generate_password | generate_seed_phrase | generate_emoji_phrase | generate_diceware_passphrase | analyze_master_strength | check_entropy | check_master_breach | get_diceware_wordlist_info | audit_params`)
}

export { server, TRANSPORT, tools }
