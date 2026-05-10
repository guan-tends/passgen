#!/usr/bin/env node
/**
 * Passgen MCP Server
 * Wraps the passgen core as an MCP-compatible tool server.
 * Phase 3 — Stateless Deterministic Passphrases, Everywhere
 */
import { createRequire } from 'module'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { createSimpleServer } from '@l4t/mcp-ai/dist/simple-server/index.js'
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
  MIN_WORD_LENGTH,
  MAX_WORD_LENGTH,
  DEFAULT_WORD_LENGTH,
  DEFAULT_SYMBOL_RATIO,
  DEFAULT_VERSION,
} = passgen

// ── Transport Detection ───────────────────────────────
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
    inputSchema: z.object({
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
    }),
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
    name: 'check_entropy',
    description: 'Estimate the entropy (strength) of a master secret or generated password. Returns bits of entropy and a human-readable classification.',
    inputSchema: z.object({
      master: z.string().optional().describe('Master secret to evaluate. If provided, estimates its entropy.'),
      password: z.string().optional().describe('Generated password to evaluate. If provided, estimates its Shannon entropy.'),
    }),
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
    inputSchema: z.object({
      service: z.string().default('service').describe('Service name.'),
      identity: z.string().default('user').describe('User identity.'),
      length: z.number().int().default(DEFAULT_WORD_LENGTH).describe('Password length.'),
      symbols: z.boolean().default(false).describe('Include symbols.'),
      caps: z.boolean().default(false).describe('Include caps.'),
      emoji: z.boolean().default(false).describe('Include emoji.'),
      symbolRatio: z.number().default(DEFAULT_SYMBOL_RATIO).describe('Symbol ratio %.'),
      emojiRatio: z.number().default(24).describe('Emoji ratio %.'),
      version: z.number().int().default(DEFAULT_VERSION).describe('Derivation version.'),
    }),
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
  console.log(`[Passgen MCP] Tools: generate_password | check_entropy | audit_params`)
}

export { server, TRANSPORT, tools }
