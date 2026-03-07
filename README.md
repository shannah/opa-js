# opa-js

Minimal JavaScript library for creating [Open Prompt Archive (OPA)](https://github.com/shannah/opa-spec) files. Works in the browser and Node.js. Supports digital signing and verification per the [OPA security spec](https://github.com/shannah/opa-spec/blob/main/specification/security.md).

An OPA file is a ZIP archive that packages an AI prompt together with data files and optional session history into a single portable file. Any OPA-compatible client can open and execute it.

## Install

```
npm install opa-js
```

## Quick Start

### Node.js

```js
import { OpaArchive, SessionHistory } from 'opa-js';

const archive = new OpaArchive({ title: 'Summarize Sales Data' });
archive.setPrompt('Summarize the CSV files in `data/`.');
archive.addDataFile('q1.csv', 'region,sales\nnorth,100\nsouth,200');

await archive.writeToFile('sales-summary.opa');
```

### Signed archive (Node.js)

```js
import { readFileSync } from 'fs';
import { OpaArchive, verifyOpaArchive } from 'opa-js';

const privateKey = readFileSync('key.pem', 'utf-8');
const certificate = readFileSync('cert.pem', 'utf-8');

// Create and sign
const archive = new OpaArchive({ title: 'Signed Task' });
archive.setPrompt('Analyze the data.');
archive.addDataFile('report.csv', csvData);

await archive.writeSignedToFile('task.opa', privateKey, certificate);

// Verify
const bytes = readFileSync('task.opa');
const result = await verifyOpaArchive(new Uint8Array(bytes), certificate);
console.log(result);
// { valid: true, signed: true }
```

### Signed archive (Browser — Web Crypto)

Uses the Web Crypto API with non-extractable ECDSA P-256 keys. The private key never leaves the browser's secure key store.

```js
import { OpaArchive, generateSigningKey, getPublicKeyFingerprint, verifyOpaArchive } from 'opa-js';

// Generate a key pair (store in IndexedDB for reuse)
const { privateKey, publicKey } = await generateSigningKey();

// Get the fingerprint for TOFU trust decisions
const fingerprint = await getPublicKeyFingerprint(publicKey);
console.log(fingerprint); // "sha256:a3f8b2c1..."

// Create and sign
const archive = new OpaArchive({ title: 'Browser Signed' });
archive.setPrompt('Analyze the data.');
archive.addDataFile('report.csv', csvString);

const blob = await archive.toSignedBlob(privateKey, publicKey);

// Download the signed .opa file
const a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'task.opa';
a.click();
```

Verification extracts the certificate from the PKCS#7 block and returns the public key fingerprint:

```js
const result = await verifyOpaArchive(archiveBytes);
console.log(result);
// { valid: true, signed: true, publicKeyFingerprint: "sha256:a3f8b2c1..." }
```

### Browser (with bundler — Vite, webpack, etc.)

```js
import { OpaArchive } from 'opa-js';

const archive = new OpaArchive({ title: 'My Task' });
archive.setPrompt('Analyze the attached data.');
archive.addDataFile('report.csv', csvString);

// Trigger download
const blob = archive.toBlob();
const a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'task.opa';
a.click();
```

### Browser (no bundler)

Use the pre-built bundle from `dist/`. It includes all dependencies so no import map is needed.

**ESM:**

```html
<script type="module">
  import { OpaArchive } from 'https://unpkg.com/opa-js/dist/opa.min.js';

  const archive = new OpaArchive({ title: 'My Task' });
  archive.setPrompt('Hello, agent!');
  const blob = archive.toBlob();
</script>
```

**Classic script tag (UMD):**

```html
<script src="https://unpkg.com/opa-js/dist/opa.umd.min.js"></script>
<script>
  const archive = new OPA.OpaArchive({ title: 'My Task' });
  archive.setPrompt('Hello, agent!');
  const blob = archive.toBlob();
</script>
```

## API

### `new OpaArchive(options?)`

Create a new archive builder.

| Option | Type | Description |
|--------|------|-------------|
| `title` | `string` | Short title for the task |
| `description` | `string` | One-line summary |
| `agentHint` | `string` | Model hint (e.g., `claude-sonnet`, `gpt-4o`) |
| `executionMode` | `string` | `interactive`, `batch`, or `autonomous` |
| `createdBy` | `string` | Tool that created the archive |

All options are optional.

#### Prompt

- **`setPrompt(content, filename?)`** — Set the prompt (Markdown string). Default filename is `prompt.md`.

#### Data files

- **`addDataFile(path, content)`** — Add a file under `data/`. `content` can be a string or `Uint8Array`.
- **`addDataFileFromPath(archivePath, diskPath)`** — Add a file from disk *(Node.js only)*.
- **`addDataDirectory(dirPath, prefix?)`** — Recursively add a directory *(Node.js only)*.

#### Session history

- **`setSession(session)`** — Attach session history. Pass a `SessionHistory` instance or a plain object matching the [session history schema](https://github.com/shannah/opa-spec/blob/main/specification/session-history.md).
- **`addSessionAttachment(path, content)`** — Add a file under `session/attachments/`.

#### Output (unsigned)

- **`toUint8Array()`** — Returns the archive as a `Uint8Array` *(works everywhere)*.
- **`toBlob()`** — Returns a `Blob` with MIME type `application/vnd.opa+zip` *(browser)*.
- **`toBuffer()`** — Returns a Node.js `Buffer` *(Node.js)*.
- **`writeToFile(path)`** — Write the archive to disk *(Node.js only)*.

#### Output (signed)

- **`toSignedUint8Array(privateKey, certOrPublicKey)`** — Returns a signed archive as a `Uint8Array`. Auto-detects PEM strings (Node.js) vs CryptoKey objects (browser). Async.
- **`toSignedBlob(privateKey, publicKey)`** — Returns a signed `Blob` *(browser)*. Async.
- **`writeSignedToFile(path, privateKeyPEM, certificatePEM)`** — Write a signed archive to disk *(Node.js only)*. Async.

Signing adds `META-INF/SIGNATURE.SF` and `META-INF/SIGNATURE.RSA` (or `.EC`) to the archive following the [JAR signing convention](https://github.com/shannah/opa-spec/blob/main/specification/security.md#signing). The manifest is enhanced with per-entry SHA-256 digests.

### `verifyOpaArchive(data, certOrPublicKey?)`

Verify a signed OPA archive. Works in both Node.js and the browser. Returns a promise.

```js
import { verifyOpaArchive } from 'opa-js';

// Node.js: pass PEM certificate
const result = await verifyOpaArchive(archiveBytes, certificatePEM);

// Browser: pass CryptoKey, or omit to extract from embedded certificate (TOFU)
const result = await verifyOpaArchive(archiveBytes);
```

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `boolean` | `true` if all checks pass |
| `signed` | `boolean` | `true` if the archive contains signature files |
| `error` | `string?` | Description of the first failure (if any) |
| `publicKeyFingerprint` | `string?` | SHA-256 fingerprint of the signer's public key (browser path) |

Verification checks:
1. PKCS#7 digital signature on `SIGNATURE.SF`
2. SHA-256 digest of `MANIFEST.MF` matches `SIGNATURE.SF`
3. Per-entry section digests in `SIGNATURE.SF` match `MANIFEST.MF`
4. Actual file contents match SHA-256 digests in `MANIFEST.MF`

Unsigned archives return `{ valid: true, signed: false }`.

### `generateSigningKey()`

Generate an ECDSA P-256 key pair for browser signing. The private key is non-extractable.

```js
const { privateKey, publicKey } = await generateSigningKey();
// Store in IndexedDB for persistence across sessions
```

### `getPublicKeyFingerprint(publicKey)`

Compute a SHA-256 fingerprint of a public key for trust-on-first-use (TOFU) decisions.

```js
const fingerprint = await getPublicKeyFingerprint(publicKey);
// "sha256:a3f8b2c1d4e5..."
```

### `new SessionHistory(sessionId?)`

Helper for building session history.

```js
const session = new SessionHistory();
session.addMessage('user', 'What does the data show?');
session.addMessage('assistant', 'The data shows a 15% increase in Q1.');
archive.setSession(session);
```

- **`addMessage(role, content, options?)`** — Add a message.
  - `role`: `user`, `assistant`, `system`, or `tool`
  - `content`: string or array of content blocks
  - `options.id`: message ID (auto-incremented if omitted)
  - `options.timestamp`: ISO 8601 (defaults to now)
  - `options.metadata`: arbitrary metadata object

### Manifest fields

Set individually via chaining:

```js
archive
  .setTitle('My Task')
  .setDescription('Process the data')
  .setAgentHint('claude-sonnet')
  .setExecutionMode('batch')
  .setCreatedBy('my-app 1.0');
```

## Generating signing keys

To create a self-signed RSA key pair for testing:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=My Name"
```

For EC keys:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=My Name"
```

## Example

The repo includes a browser example that fetches an RSS feed and packages it into an OPA file:

```
npm run example
```

Then open http://localhost:3000. See [`examples/browser-rss.html`](./examples/browser-rss.html).

## Build

To rebuild the browser bundles (`dist/opa.min.js` and `dist/opa.umd.min.js`):

```
npm run build
```

## Test

```
npm test
```

## Bundle sizes

| File | Size | Use case |
|------|------|----------|
| `dist/opa.min.js` | ~12 KB | ESM import (browser, no bundler) |
| `dist/opa.umd.min.js` | ~13 KB | `<script>` tag (global `OPA`) |
| `src/index.js` | ~6 KB | Bundler or Node.js (fflate resolved separately) |

Signing works in both environments: Node.js uses PEM keys with the built-in `crypto` module; browsers use the Web Crypto API with ECDSA P-256 keys.

## License

MIT
