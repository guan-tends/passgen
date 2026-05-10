/**
 * Phase 3 — MCP Server Tests
 * Test tool execute functions directly (no transport-layer testing)
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// Dynamically import the ESM module to extract tools
let tools = [];
let generatePassword, checkEntropy, auditParams;

describe('Phase 3: MCP Server Tools', async () => {
  // Load tools from ESM module via dynamic import
  tools = (await import('../mcp-server.mjs')).tools;
  generatePassword = tools.find(t => t.name === 'generate_password');
  checkEntropy = tools.find(t => t.name === 'check_entropy');
  auditParams = tools.find(t => t.name === 'audit_params');

  let generateSeedPhrase, generateEmojiPhrase;

  // Resolve all tool handles at suite level
  generateSeedPhrase = tools.find(t => t.name === 'generate_seed_phrase');
  generateEmojiPhrase = tools.find(t => t.name === 'generate_emoji_phrase');

  it('loads all nine tools', () => {
    assert.strictEqual(tools.length, 9);
    assert.ok(generatePassword, 'generate_password tool exists');
    assert.ok(checkEntropy, 'check_entropy tool exists');
    assert.ok(auditParams, 'audit_params tool exists');
    assert.ok(generateSeedPhrase, 'generate_seed_phrase tool exists');
    assert.ok(generateEmojiPhrase, 'generate_emoji_phrase tool exists');
  });

  it('generate_password returns correct length', async () => {
    const result = await generatePassword.execute({
      master: 'brainwallet-test',
      service: 'github',
      identity: 'personal',
      length: 32,
      symbols: false,
      caps: false,
      emoji: false,
      symbolRatio: 0,
      emojiRatio: 0,
      version: 2,
    });
    assert.ok(!result.isError, result.content?.[0]?.text);
    const pwd = result.content[0].text;
    assert.strictEqual(pwd.length, 32);
  });

  it('generate_password rejects empty master', async () => {
    const result = await generatePassword.execute({
      master: '',
      service: 'test',
      identity: 'test',
      length: 16,
      symbols: false,
      caps: false,
      emoji: false,
      symbolRatio: 0,
      emojiRatio: 0,
      version: 2,
    });
    assert.strictEqual(result.isError, true);
    assert.ok(result.content[0].text.includes('master secret is required'));
  });

  it('generate_password v1 differs from v2', async () => {
    const v1 = await generatePassword.execute({
      master: 'same', service: 'svc', identity: 'me',
      length: 32, symbols: false, caps: false, emoji: false,
      symbolRatio: 0, emojiRatio: 0, version: 1,
    });
    const v2 = await generatePassword.execute({
      master: 'same', service: 'svc', identity: 'me',
      length: 32, symbols: false, caps: false, emoji: false,
      symbolRatio: 0, emojiRatio: 0, version: 2,
    });
    assert.notStrictEqual(v1.content[0].text, v2.content[0].text);
  });

  it('generate_password with symbols+caps changes output', async () => {
    const plain = await generatePassword.execute({
      master: 'test', service: 'svc', identity: 'me',
      length: 32, symbols: false, caps: false, emoji: false,
      symbolRatio: 0, emojiRatio: 0, version: 2,
    });
    const fancy = await generatePassword.execute({
      master: 'test', service: 'svc', identity: 'me',
      length: 32, symbols: true, caps: true, emoji: false,
      symbolRatio: 50, emojiRatio: 0, version: 2,
    });
    assert.notStrictEqual(plain.content[0].text, fancy.content[0].text);
  });

  it('check_entropy classifies weak master', async () => {
    const result = await checkEntropy.execute({ master: 'abc' });
    assert.ok(!result.isError);
    assert.ok(result.content[0].text.includes('bits'));
    assert.ok(result.content[0].text.includes('Weak') || result.content[0].text.includes('Very Weak'));
  });

  it('check_entropy classifies strong master', async () => {
    const result = await checkEntropy.execute({
      master: 'super.duper.extra.long.passphrase!123$%^',
    });
    assert.ok(!result.isError);
    assert.ok(result.content[0].text.includes('Very Strong') || result.content[0].text.includes('Strong'));
  });

  it('check_entropy handles both master and password', async () => {
    const result = await checkEntropy.execute({
      master: 'test',
      password: 'abcdefghijklmnopqrstuvwxyz012345',
    });
    assert.ok(!result.isError);
    assert.ok(result.content[0].text.includes('Master secret:'));
    assert.ok(result.content[0].text.includes('Password:'));
  });

  it('check_entropy errors on empty input', async () => {
    const result = await checkEntropy.execute({});
    assert.strictEqual(result.isError, true);
  });

  it('audit_params returns 64-char hex digest', async () => {
    const result = await auditParams.execute({
      service: 'github',
      identity: 'personal',
      length: 32,
      symbols: false,
      caps: false,
      emoji: false,
      symbolRatio: 0,
      emojiRatio: 0,
      version: 2,
    });
    assert.ok(!result.isError);
    // Extract hex from "Audit digest: <hex>\nCompare ..."
    const match = result.content[0].text.match(/Audit digest: ([a-f0-9]+)/);
    assert.ok(match, 'Audit digest found');
    assert.strictEqual(match[1].length, 64, 'Digest is SHA3-256 hex');
  });

  it('audit_params is deterministic for same parameters', async () => {
    const params = {
      service: 'test', identity: 'me', length: 16,
      symbols: false, caps: false, emoji: false,
      symbolRatio: 0, emojiRatio: 0, version: 2,
    };
    const a = await auditParams.execute(params);
    const b = await auditParams.execute(params);
    const digestA = a.content[0].text.match(/Audit digest: ([a-f0-9]+)/)[1];
    const digestB = b.content[0].text.match(/Audit digest: ([a-f0-9]+)/)[1];
    assert.strictEqual(digestA, digestB);
  });

  // ── Phase 5: Seed Phrase + Emoji Phrase Tools ──

  it('generate_seed_phrase returns correct word count', async () => {
    const result = await generateSeedPhrase.execute({ master: 'test-seed', wordCount: 12 });
    assert.ok(!result.isError);
    const phrase = result.content[0].text.split('\n')[0];
    assert.strictEqual(phrase.split(' ').length, 12);
  });

  it('generate_seed_phrase is deterministic', async () => {
    const a = await generateSeedPhrase.execute({ master: 'same-master', wordCount: 24 });
    const b = await generateSeedPhrase.execute({ master: 'same-master', wordCount: 24 });
    const phraseA = a.content[0].text.split('\n')[0];
    const phraseB = b.content[0].text.split('\n')[0];
    assert.strictEqual(phraseA, phraseB);
  });

  it('generate_seed_phrase rejects empty master', async () => {
    const result = await generateSeedPhrase.execute({ master: '', wordCount: 12 });
    assert.strictEqual(result.isError, true);
  });

  it('generate_seed_phrase rejects invalid word count', async () => {
    const result = await generateSeedPhrase.execute({ master: 'test', wordCount: 13 });
    assert.strictEqual(result.isError, true);
  });

  it('generate_emoji_phrase returns correct symbol count', async () => {
    const result = await generateEmojiPhrase.execute({ master: 'test-emoji', count: 12 });
    assert.ok(!result.isError);
    const phrase = result.content[0].text.split('\n')[0];
    assert.strictEqual(phrase.split(' ').length, 12);
  });

  it('generate_emoji_phrase is deterministic', async () => {
    const a = await generateEmojiPhrase.execute({ master: 'same-emoji', count: 8 });
    const b = await generateEmojiPhrase.execute({ master: 'same-emoji', count: 8 });
    const phraseA = a.content[0].text.split('\n')[0];
    const phraseB = b.content[0].text.split('\n')[0];
    assert.strictEqual(phraseA, phraseB);
  });

  it('generate_emoji_phrase rejects count > 64', async () => {
    const result = await generateEmojiPhrase.execute({ master: 'test', count: 65 });
    assert.strictEqual(result.isError, true);
  });
});
