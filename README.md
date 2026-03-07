# opa-js

Minimal JavaScript library for creating [Open Prompt Archive (OPA)](./RFC-0001-OPA.md) files. Works in the browser and Node.js.

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

- **`setSession(session)`** — Attach session history. Pass a `SessionHistory` instance or a plain object matching the [schema](./RFC-0001-OPA.md#7-session-history).
- **`addSessionAttachment(path, content)`** — Add a file under `session/attachments/`.

#### Output

- **`toUint8Array()`** — Returns the archive as a `Uint8Array` *(works everywhere)*.
- **`toBlob()`** — Returns a `Blob` with MIME type `application/vnd.opa+zip` *(browser)*.
- **`toBuffer()`** — Returns a Node.js `Buffer` *(Node.js)*.
- **`writeToFile(path)`** — Write the archive to disk *(Node.js only)*.

All methods except the async Node.js ones are synchronous. The builder supports method chaining.

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
  - `content`: string or array of [content blocks](./RFC-0001-OPA.md#722-content-blocks)
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

## License

MIT
