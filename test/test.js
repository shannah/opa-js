import { OpaArchive, SessionHistory, verifyOpaArchive } from '../src/index.js';
import { unzipSync, strFromU8 } from 'fflate';
import { strict as assert } from 'node:assert';
import { mkdtemp, writeFile, mkdir, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execSync } from 'node:child_process';

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

function readZipEntry(zip, path) {
  const entry = zip[path];
  if (!entry) throw new Error(`Missing entry: ${path}`);
  return strFromU8(entry);
}

console.log('OpaArchive tests\n');

// ── Minimal archive ──

await test('creates a minimal valid OPA archive', () => {
  const archive = new OpaArchive();
  archive.setPrompt('Hello, agent!');
  const data = archive.toUint8Array();

  assert(data instanceof Uint8Array);
  assert(data.length > 0);

  const zip = unzipSync(data);
  const manifest = readZipEntry(zip, 'META-INF/MANIFEST.MF');
  assert(manifest.includes('Manifest-Version: 1.0'));
  assert(manifest.includes('OPA-Version: 0.1'));
  assert(manifest.includes('Prompt-File: prompt.md'));

  const prompt = readZipEntry(zip, 'prompt.md');
  assert.equal(prompt, 'Hello, agent!');
});

// ── Manifest fields ──

await test('includes optional manifest fields', () => {
  const archive = new OpaArchive({
    title: 'Test Task',
    description: 'A test archive',
    agentHint: 'claude-sonnet',
    executionMode: 'batch',
    createdBy: 'opa-js-test',
  });
  archive.setPrompt('Do something.');
  const zip = unzipSync(archive.toUint8Array());
  const manifest = readZipEntry(zip, 'META-INF/MANIFEST.MF');
  assert(manifest.includes('Title: Test Task'));
  assert(manifest.includes('Description: A test archive'));
  assert(manifest.includes('Agent-Hint: claude-sonnet'));
  assert(manifest.includes('Execution-Mode: batch'));
  assert(manifest.includes('Created-By: opa-js-test'));
  assert(manifest.includes('Created-At:'));
});

// ── Long manifest lines ──

await test('wraps long manifest lines at 72 bytes', () => {
  const archive = new OpaArchive();
  archive.setPrompt('test');
  archive.setDescription('This is a very long description that should definitely exceed the seventy-two byte line limit in the manifest');
  const zip = unzipSync(archive.toUint8Array());
  const manifest = readZipEntry(zip, 'META-INF/MANIFEST.MF');
  const lines = manifest.split('\r\n');
  for (const line of lines) {
    assert(line.length <= 72, `Line too long (${line.length}): "${line}"`);
  }
});

// ── Data files ──

await test('adds data files to archive', () => {
  const archive = new OpaArchive();
  archive.setPrompt('Analyze the data.');
  archive.addDataFile('report.csv', 'a,b,c\n1,2,3');
  archive.addDataFile('sub/nested.txt', 'nested content');

  const zip = unzipSync(archive.toUint8Array());
  assert.equal(readZipEntry(zip, 'data/report.csv'), 'a,b,c\n1,2,3');
  assert.equal(readZipEntry(zip, 'data/sub/nested.txt'), 'nested content');
});

await test('accepts Uint8Array data', () => {
  const archive = new OpaArchive();
  archive.setPrompt('test');
  const binary = new Uint8Array([0x89, 0x50, 0x4e, 0x47]); // PNG header
  archive.addDataFile('image.png', binary);

  const zip = unzipSync(archive.toUint8Array());
  assert.deepEqual(zip['data/image.png'], binary);
});

// ── Session history ──

await test('includes session history', () => {
  const session = new SessionHistory('test-uuid-1234');
  session.addMessage('user', 'Hello');
  session.addMessage('assistant', 'Hi there!');

  const archive = new OpaArchive();
  archive.setPrompt('Continue the conversation.');
  archive.setSession(session);

  const zip = unzipSync(archive.toUint8Array());
  const history = JSON.parse(readZipEntry(zip, 'session/history.json'));
  assert.equal(history.opa_version, '0.1');
  assert.equal(history.session_id, 'test-uuid-1234');
  assert.equal(history.messages.length, 2);
  assert.equal(history.messages[0].role, 'user');
  assert.equal(history.messages[0].content, 'Hello');
  assert.equal(history.messages[1].role, 'assistant');

  const manifest = readZipEntry(zip, 'META-INF/MANIFEST.MF');
  assert(manifest.includes('Session-File: session/history.json'));
});

await test('supports plain object session history', () => {
  const archive = new OpaArchive();
  archive.setPrompt('test');
  archive.setSession({
    opa_version: '0.1',
    session_id: 'custom-id',
    messages: [{ role: 'user', content: 'test' }],
  });

  const zip = unzipSync(archive.toUint8Array());
  const history = JSON.parse(readZipEntry(zip, 'session/history.json'));
  assert.equal(history.session_id, 'custom-id');
});

await test('includes session attachments', () => {
  const session = new SessionHistory();
  session.addMessage('user', [
    { type: 'text', text: 'See the image' },
    { type: 'image', source: { type: 'attachment', path: 'session/attachments/photo.png' } },
  ]);

  const archive = new OpaArchive();
  archive.setPrompt('test');
  archive.setSession(session);
  archive.addSessionAttachment('photo.png', new Uint8Array([1, 2, 3]));

  const zip = unzipSync(archive.toUint8Array());
  assert.deepEqual(zip['session/attachments/photo.png'], new Uint8Array([1, 2, 3]));
});

// ── Path safety ──

await test('rejects absolute paths', () => {
  const archive = new OpaArchive();
  assert.throws(() => archive.addDataFile('/etc/passwd', 'bad'), /Absolute paths/);
});

await test('rejects path traversal', () => {
  const archive = new OpaArchive();
  assert.throws(() => archive.addDataFile('../escape.txt', 'bad'), /Path traversal/);
  assert.throws(() => archive.addDataFile('foo/../../bar', 'bad'), /Path traversal/);
});

// ── Errors ──

await test('throws if no prompt set', () => {
  const archive = new OpaArchive();
  assert.throws(() => archive.toUint8Array(), /Prompt content is required/);
});

await test('rejects invalid execution mode', () => {
  const archive = new OpaArchive();
  assert.throws(() => archive.setExecutionMode('invalid'), /Invalid execution mode/);
});

// ── Fluent API ──

await test('supports method chaining', () => {
  const data = new OpaArchive()
    .setPrompt('chained')
    .setTitle('Chained')
    .setDescription('test')
    .addDataFile('a.txt', 'hello')
    .toUint8Array();
  assert(data.length > 0);
});

// ── Node.js file operations ──

await test('writeToFile writes a valid OPA file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'opa-test-'));
  const outPath = join(dir, 'test.opa');
  try {
    const archive = new OpaArchive({ title: 'File Test' });
    archive.setPrompt('Written to disk.');
    await archive.writeToFile(outPath);
    const bytes = await readFile(outPath);
    const zip = unzipSync(new Uint8Array(bytes));
    assert.equal(readZipEntry(zip, 'prompt.md'), 'Written to disk.');
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test('addDataDirectory adds files recursively', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'opa-test-'));
  try {
    await mkdir(join(dir, 'sub'), { recursive: true });
    await writeFile(join(dir, 'root.txt'), 'root');
    await writeFile(join(dir, 'sub', 'child.txt'), 'child');

    const archive = new OpaArchive();
    archive.setPrompt('test');
    await archive.addDataDirectory(dir);

    const zip = unzipSync(archive.toUint8Array());
    assert.equal(readZipEntry(zip, 'data/root.txt'), 'root');
    assert.equal(readZipEntry(zip, 'data/sub/child.txt'), 'child');
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test('addDataFileFromPath reads a file from disk', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'opa-test-'));
  try {
    await writeFile(join(dir, 'source.csv'), 'x,y\n1,2');

    const archive = new OpaArchive();
    archive.setPrompt('test');
    await archive.addDataFileFromPath('imported.csv', join(dir, 'source.csv'));

    const zip = unzipSync(archive.toUint8Array());
    assert.equal(readZipEntry(zip, 'data/imported.csv'), 'x,y\n1,2');
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ── toBuffer ──

await test('toBuffer returns a Node.js Buffer', () => {
  const archive = new OpaArchive();
  archive.setPrompt('test');
  const buf = archive.toBuffer();
  assert(Buffer.isBuffer(buf));
  // Verify it starts with PK zip signature
  assert.equal(buf[0], 0x50); // P
  assert.equal(buf[1], 0x4b); // K
});

// ── Signing ──

// Generate a test RSA key pair and self-signed certificate
const testKeyDir = await mkdtemp(join(tmpdir(), 'opa-keys-'));
const keyPath = join(testKeyDir, 'test.key');
const certPath = join(testKeyDir, 'test.crt');
execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 1 -nodes -subj "/CN=OPA Test" 2>/dev/null`);
const testPrivateKey = (await readFile(keyPath, 'utf-8'));
const testCertificate = (await readFile(certPath, 'utf-8'));

console.log('\nSigning tests\n');

await test('creates a signed archive with SIGNATURE.SF and SIGNATURE.RSA', async () => {
  const archive = new OpaArchive({ title: 'Signed Test', createdBy: 'opa-js-test' });
  archive.setPrompt('Signed prompt.');
  archive.addDataFile('report.csv', 'a,b\n1,2');

  const data = await archive.toSignedUint8Array(testPrivateKey, testCertificate);
  const zip = unzipSync(data);

  // Should have signature files
  assert(zip['META-INF/SIGNATURE.SF'], 'Missing SIGNATURE.SF');
  assert(zip['META-INF/SIGNATURE.RSA'], 'Missing SIGNATURE.RSA');

  // SIGNATURE.SF should contain expected fields
  const sf = strFromU8(zip['META-INF/SIGNATURE.SF']);
  assert(sf.includes('Signature-Version: 1.0'), 'Missing Signature-Version');
  assert(sf.includes('SHA-256-Digest-Manifest:'), 'Missing manifest digest');
  assert(sf.includes('Name: prompt.md'), 'Missing prompt.md section');
  assert(sf.includes('Name: data/report.csv'), 'Missing data/report.csv section');
});

await test('manifest includes per-entry SHA-256 digest sections when signed', async () => {
  const archive = new OpaArchive();
  archive.setPrompt('test');
  archive.addDataFile('info.txt', 'hello');

  const data = await archive.toSignedUint8Array(testPrivateKey, testCertificate);
  const zip = unzipSync(data);
  const manifest = strFromU8(zip['META-INF/MANIFEST.MF']);

  assert(manifest.includes('Name: prompt.md'), 'Missing prompt.md entry section');
  assert(manifest.includes('Name: data/info.txt'), 'Missing data/info.txt entry section');
  assert(manifest.includes('SHA-256-Digest:'), 'Missing digest in entry section');
});

await test('verifyOpaArchive returns valid for correctly signed archive', async () => {
  const archive = new OpaArchive({ title: 'Verify Test' });
  archive.setPrompt('Verifiable prompt.');
  archive.addDataFile('data.txt', 'some data');

  const data = await archive.toSignedUint8Array(testPrivateKey, testCertificate);
  const result = await verifyOpaArchive(data, testCertificate);

  assert.equal(result.valid, true, `Expected valid but got: ${result.error}`);
  assert.equal(result.signed, true);
});

await test('verifyOpaArchive detects tampered prompt', async () => {
  const archive = new OpaArchive();
  archive.setPrompt('Original prompt.');

  const data = await archive.toSignedUint8Array(testPrivateKey, testCertificate);
  const zip = unzipSync(data);

  // Tamper with the prompt
  zip['prompt.md'] = new TextEncoder().encode('Tampered prompt!');

  // Re-zip (need fflate zipSync)
  const { zipSync: rezip } = await import('fflate');
  const tampered = rezip(zip, { level: 6 });

  const result = await verifyOpaArchive(tampered, testCertificate);
  assert.equal(result.valid, false);
  assert.equal(result.signed, true);
});

await test('verifyOpaArchive reports unsigned archives', async () => {
  const archive = new OpaArchive();
  archive.setPrompt('Unsigned.');

  const data = archive.toUint8Array();
  const result = await verifyOpaArchive(data);

  assert.equal(result.signed, false);
  assert.equal(result.valid, true); // unsigned is not invalid, just unsigned
});

await test('verifyOpaArchive rejects wrong certificate', async () => {
  const archive = new OpaArchive();
  archive.setPrompt('test');

  const data = await archive.toSignedUint8Array(testPrivateKey, testCertificate);

  // Generate a different certificate
  const key2Path = join(testKeyDir, 'other.key');
  const cert2Path = join(testKeyDir, 'other.crt');
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${key2Path}" -out "${cert2Path}" -days 1 -nodes -subj "/CN=Other" 2>/dev/null`);
  const otherCert = await readFile(cert2Path, 'utf-8');

  const result = await verifyOpaArchive(data, otherCert);
  assert.equal(result.valid, false);
  assert.equal(result.signed, true);
});

await test('writeSignedToFile writes a valid signed archive', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'opa-signed-'));
  const outPath = join(dir, 'signed.opa');
  try {
    const archive = new OpaArchive({ title: 'File Signing Test' });
    archive.setPrompt('Signed to disk.');
    await archive.writeSignedToFile(outPath, testPrivateKey, testCertificate);

    const bytes = await readFile(outPath);
    const result = await verifyOpaArchive(new Uint8Array(bytes), testCertificate);
    assert.equal(result.valid, true, `Expected valid but got: ${result.error}`);
    assert.equal(result.signed, true);
  } finally {
    await rm(dir, { recursive: true });
  }
});

await test('signed archive with session history verifies correctly', async () => {
  const session = new SessionHistory('test-session');
  session.addMessage('user', 'Hello');
  session.addMessage('assistant', 'Hi!');

  const archive = new OpaArchive();
  archive.setPrompt('Continue.');
  archive.setSession(session);
  archive.addDataFile('notes.txt', 'Some notes');

  const data = await archive.toSignedUint8Array(testPrivateKey, testCertificate);
  const result = await verifyOpaArchive(data, testCertificate);
  assert.equal(result.valid, true, `Expected valid but got: ${result.error}`);

  // Verify all expected entries are in SIGNATURE.SF
  const zip = unzipSync(data);
  const sf = strFromU8(zip['META-INF/SIGNATURE.SF']);
  assert(sf.includes('Name: session/history.json'));
  assert(sf.includes('Name: data/notes.txt'));
});

// Cleanup test keys
await rm(testKeyDir, { recursive: true });

// ── Browser signing (Web Crypto API) ──

import { generateSigningKey, getPublicKeyFingerprint } from '../src/browser-signing.js';

console.log('\nBrowser signing tests (Web Crypto)\n');

await test('generateSigningKey produces a CryptoKey pair', async () => {
  const { privateKey, publicKey } = await generateSigningKey();
  assert(privateKey instanceof CryptoKey);
  assert(publicKey instanceof CryptoKey);
  assert.equal(privateKey.type, 'private');
  assert.equal(publicKey.type, 'public');
  assert.equal(privateKey.extractable, false, 'private key should be non-extractable');
  assert.equal(publicKey.extractable, true, 'public key should be extractable');
});

await test('getPublicKeyFingerprint returns consistent sha256 fingerprint', async () => {
  const { publicKey } = await generateSigningKey();
  const fp1 = await getPublicKeyFingerprint(publicKey);
  const fp2 = await getPublicKeyFingerprint(publicKey);
  assert.equal(fp1, fp2);
  assert(fp1.startsWith('sha256:'), `Expected sha256: prefix, got: ${fp1}`);
  assert.equal(fp1.length, 7 + 64, 'Expected sha256: + 64 hex chars');
});

await test('browser-signed archive contains SIGNATURE.SF and SIGNATURE.EC', async () => {
  const { privateKey, publicKey } = await generateSigningKey();
  const archive = new OpaArchive({ title: 'Browser Signed' });
  archive.setPrompt('Browser signed prompt.');
  archive.addDataFile('notes.txt', 'test data');

  const data = await archive.toSignedUint8Array(privateKey, publicKey);
  const zip = unzipSync(data);

  assert(zip['META-INF/SIGNATURE.SF'], 'Missing SIGNATURE.SF');
  assert(zip['META-INF/SIGNATURE.EC'], 'Missing SIGNATURE.EC');
  assert(!zip['META-INF/SIGNATURE.RSA'], 'Should not have SIGNATURE.RSA');

  const sf = strFromU8(zip['META-INF/SIGNATURE.SF']);
  assert(sf.includes('Signature-Version: 1.0'));
  assert(sf.includes('SHA-256-Digest-Manifest:'));
  assert(sf.includes('Name: prompt.md'));
  assert(sf.includes('Name: data/notes.txt'));
});

await test('browser-signed archive verifies without providing key (TOFU)', async () => {
  const { privateKey, publicKey } = await generateSigningKey();
  const archive = new OpaArchive({ title: 'TOFU Test' });
  archive.setPrompt('Verify without key.');

  const data = await archive.toSignedUint8Array(privateKey, publicKey);
  const result = await verifyOpaArchive(data);

  assert.equal(result.valid, true, `Expected valid but got: ${result.error}`);
  assert.equal(result.signed, true);
  assert(result.publicKeyFingerprint, 'Expected publicKeyFingerprint in result');
  assert(result.publicKeyFingerprint.startsWith('sha256:'));
});

await test('browser-signed archive verifies with provided public key', async () => {
  const { privateKey, publicKey } = await generateSigningKey();
  const archive = new OpaArchive();
  archive.setPrompt('Verify with key.');
  archive.addDataFile('data.csv', 'a,b\n1,2');

  const data = await archive.toSignedUint8Array(privateKey, publicKey);
  const result = await verifyOpaArchive(data, publicKey);

  assert.equal(result.valid, true, `Expected valid but got: ${result.error}`);
  assert.equal(result.signed, true);
});

await test('browser-signed archive detects tampering', async () => {
  const { privateKey, publicKey } = await generateSigningKey();
  const archive = new OpaArchive();
  archive.setPrompt('Original browser prompt.');

  const data = await archive.toSignedUint8Array(privateKey, publicKey);
  const zip = unzipSync(data);

  // Tamper with the prompt
  zip['prompt.md'] = new TextEncoder().encode('Tampered!');

  const { zipSync: rezip } = await import('fflate');
  const tampered = rezip(zip, { level: 6 });

  const result = await verifyOpaArchive(tampered);
  assert.equal(result.valid, false);
  assert.equal(result.signed, true);
});

await test('browser-signed archive fingerprint matches generated key', async () => {
  const { privateKey, publicKey } = await generateSigningKey();
  const expectedFP = await getPublicKeyFingerprint(publicKey);

  const archive = new OpaArchive();
  archive.setPrompt('Fingerprint test.');

  const data = await archive.toSignedUint8Array(privateKey, publicKey);
  const result = await verifyOpaArchive(data);

  assert.equal(result.publicKeyFingerprint, expectedFP);
});

await test('browser-signed archive with session history verifies', async () => {
  const { privateKey, publicKey } = await generateSigningKey();
  const session = new SessionHistory('browser-session');
  session.addMessage('user', 'Hello from browser');
  session.addMessage('assistant', 'Hi!');

  const archive = new OpaArchive();
  archive.setPrompt('Browser session test.');
  archive.setSession(session);
  archive.addDataFile('info.txt', 'Some info');

  const data = await archive.toSignedUint8Array(privateKey, publicKey);
  const result = await verifyOpaArchive(data);

  assert.equal(result.valid, true, `Expected valid but got: ${result.error}`);
  assert.equal(result.signed, true);

  const zip = unzipSync(data);
  const sf = strFromU8(zip['META-INF/SIGNATURE.SF']);
  assert(sf.includes('Name: session/history.json'));
  assert(sf.includes('Name: data/info.txt'));
});

// ── Summary ──

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
