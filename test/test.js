import { OpaArchive, SessionHistory } from '../src/index.js';
import { unzipSync, strFromU8 } from 'fflate';
import { strict as assert } from 'node:assert';
import { mkdtemp, writeFile, mkdir, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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

// ── Summary ──

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
