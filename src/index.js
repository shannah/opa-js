import { zipSync, strToU8 } from 'fflate';
import { signArchiveFiles, verifyArchive } from './signing.js';

const OPA_VERSION = '0.1';
const MANIFEST_VERSION = '1.0';

/**
 * Formats a manifest value, wrapping lines at 72 bytes per the JAR manifest spec.
 * Continuation lines start with a single space.
 */
function formatManifestLine(name, value) {
  const line = `${name}: ${value}`;
  if (line.length <= 72) return line;
  const parts = [];
  parts.push(line.slice(0, 72));
  let pos = 72;
  while (pos < line.length) {
    // Continuation lines: space + up to 71 chars = 72 bytes
    parts.push(' ' + line.slice(pos, pos + 71));
    pos += 71;
  }
  return parts.join('\r\n');
}

/**
 * Validates an archive-relative path for safety.
 * Rejects paths with ".." components or absolute paths.
 */
function validatePath(path) {
  if (path.startsWith('/')) {
    throw new Error(`Absolute paths are not allowed: ${path}`);
  }
  const parts = path.split('/');
  for (const part of parts) {
    if (part === '..') {
      throw new Error(`Path traversal ("..") is not allowed: ${path}`);
    }
  }
  return path;
}

/**
 * Encodes a string as a Uint8Array (UTF-8).
 */
function encode(str) {
  return strToU8(str);
}

// ── SessionHistory ──────────────────────────────────────────────────────

export class SessionHistory {
  /**
   * @param {string} [sessionId] - UUID v4 session identifier. Auto-generated if omitted.
   */
  constructor(sessionId) {
    this.sessionId = sessionId || crypto.randomUUID();
    const now = new Date().toISOString();
    this.createdAt = now;
    this.updatedAt = now;
    this.messages = [];
  }

  /**
   * Add a message to the session history.
   * @param {'user'|'assistant'|'system'|'tool'} role
   * @param {string|Array} content - Plain string or array of content blocks.
   * @param {object} [options]
   * @param {string} [options.id] - Message ID. Auto-incremented if omitted.
   * @param {string} [options.timestamp] - ISO 8601. Defaults to now.
   * @param {object} [options.metadata] - Arbitrary metadata.
   */
  addMessage(role, content, options = {}) {
    const id = options.id || String(this.messages.length + 1);
    const timestamp = options.timestamp || new Date().toISOString();
    const msg = { id, role, content, timestamp };
    if (options.metadata) msg.metadata = options.metadata;
    this.messages.push(msg);
    this.updatedAt = timestamp;
    return this;
  }

  toJSON() {
    return {
      opa_version: OPA_VERSION,
      session_id: this.sessionId,
      created_at: this.createdAt,
      updated_at: this.updatedAt,
      messages: this.messages,
    };
  }
}

// ── OpaArchive ──────────────────────────────────────────────────────────

export class OpaArchive {
  /**
   * @param {object} [options]
   * @param {string} [options.title]
   * @param {string} [options.description]
   * @param {string} [options.agentHint]
   * @param {'interactive'|'batch'|'autonomous'} [options.executionMode]
   * @param {string} [options.createdBy]
   */
  constructor(options = {}) {
    this._title = options.title || null;
    this._description = options.description || null;
    this._agentHint = options.agentHint || null;
    this._executionMode = options.executionMode || null;
    this._createdBy = options.createdBy || null;
    this._promptFile = 'prompt.md';
    this._promptContent = null;
    this._session = null;
    this._dataFiles = new Map(); // relativePath -> Uint8Array
    this._sessionAttachments = new Map(); // relativePath -> Uint8Array
  }

  // ── Prompt ──

  /**
   * Set the prompt content (Markdown string).
   * @param {string} content
   * @param {string} [filename='prompt.md'] - Custom prompt filename.
   */
  setPrompt(content, filename) {
    this._promptContent = content;
    if (filename) this._promptFile = filename;
    return this;
  }

  // ── Manifest fields ──

  setTitle(title) { this._title = title; return this; }
  setDescription(desc) { this._description = desc; return this; }
  setAgentHint(hint) { this._agentHint = hint; return this; }
  setCreatedBy(tool) { this._createdBy = tool; return this; }

  setExecutionMode(mode) {
    const valid = ['interactive', 'batch', 'autonomous'];
    if (!valid.includes(mode)) {
      throw new Error(`Invalid execution mode "${mode}". Must be one of: ${valid.join(', ')}`);
    }
    this._executionMode = mode;
    return this;
  }

  // ── Data files ──

  /**
   * Add a file to the data/ directory.
   * @param {string} relativePath - Path relative to data/ (e.g., "report.csv" or "q1/north.csv").
   * @param {string|Uint8Array} content
   */
  addDataFile(relativePath, content) {
    validatePath(relativePath);
    const data = typeof content === 'string' ? encode(content) : content;
    this._dataFiles.set(relativePath, data);
    return this;
  }

  /**
   * Add a data file from the filesystem (Node.js only).
   * @param {string} relativePath - Path inside data/ in the archive.
   * @param {string} filePath - Absolute path on disk.
   */
  async addDataFileFromPath(relativePath, filePath) {
    const fs = await import('node:fs/promises');
    const content = await fs.readFile(filePath);
    return this.addDataFile(relativePath, new Uint8Array(content));
  }

  /**
   * Recursively add all files from a directory into data/ (Node.js only).
   * @param {string} dirPath - Absolute path to a directory.
   * @param {string} [prefix=''] - Prefix within data/ for these files.
   */
  async addDataDirectory(dirPath, prefix = '') {
    const fs = await import('node:fs/promises');
    const path = await import('node:path');
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      const archivePath = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        await this.addDataDirectory(fullPath, archivePath);
      } else {
        const content = await fs.readFile(fullPath);
        this.addDataFile(archivePath, new Uint8Array(content));
      }
    }
    return this;
  }

  // ── Session ──

  /**
   * Set the session history.
   * @param {SessionHistory|object} session - A SessionHistory instance or a plain object matching the schema.
   */
  setSession(session) {
    this._session = session;
    return this;
  }

  /**
   * Add an attachment to the session.
   * @param {string} relativePath - Path relative to session/attachments/ (e.g., "image.png").
   * @param {string|Uint8Array} content
   */
  addSessionAttachment(relativePath, content) {
    validatePath(relativePath);
    const data = typeof content === 'string' ? encode(content) : content;
    this._sessionAttachments.set(relativePath, data);
    return this;
  }

  // ── Build ──

  /** Build the manifest main section string. */
  _buildManifest() {
    const lines = [];
    lines.push(formatManifestLine('Manifest-Version', MANIFEST_VERSION));
    lines.push(formatManifestLine('OPA-Version', OPA_VERSION));
    lines.push(formatManifestLine('Prompt-File', this._promptFile));
    if (this._title) lines.push(formatManifestLine('Title', this._title));
    if (this._description) lines.push(formatManifestLine('Description', this._description));
    if (this._createdBy) lines.push(formatManifestLine('Created-By', this._createdBy));
    lines.push(formatManifestLine('Created-At', new Date().toISOString()));
    if (this._agentHint) lines.push(formatManifestLine('Agent-Hint', this._agentHint));
    if (this._executionMode) lines.push(formatManifestLine('Execution-Mode', this._executionMode));
    if (this._session) lines.push(formatManifestLine('Session-File', 'session/history.json'));
    // Manifest must end with a newline
    return lines.join('\r\n') + '\r\n';
  }

  /** Collect all archive content files (everything except META-INF). */
  _collectFiles() {
    if (!this._promptContent) {
      throw new Error('Prompt content is required. Call setPrompt() before building.');
    }

    const files = {};

    // Prompt file
    files[this._promptFile] = encode(this._promptContent);

    // Session
    if (this._session) {
      const sessionData = this._session instanceof SessionHistory
        ? this._session.toJSON()
        : this._session;
      files['session/history.json'] = encode(JSON.stringify(sessionData, null, 2));

      for (const [relPath, data] of this._sessionAttachments) {
        files[`session/attachments/${relPath}`] = data;
      }
    }

    // Data files
    for (const [relPath, data] of this._dataFiles) {
      files[`data/${relPath}`] = data;
    }

    return files;
  }

  /**
   * Build the archive and return it as a Uint8Array (works everywhere).
   * @returns {Uint8Array}
   */
  toUint8Array() {
    const files = this._collectFiles();
    files['META-INF/MANIFEST.MF'] = encode(this._buildManifest());
    return zipSync(files, { level: 6 });
  }

  /**
   * Build a signed archive and return it as a Uint8Array (Node.js only).
   * @param {string} privateKeyPEM - PEM-encoded private key (RSA or EC).
   * @param {string} certificatePEM - PEM-encoded X.509 certificate.
   * @returns {Promise<Uint8Array>}
   */
  async toSignedUint8Array(privateKeyPEM, certificatePEM) {
    const files = this._collectFiles();
    const mainManifest = this._buildManifest();
    await signArchiveFiles(files, mainManifest, privateKeyPEM, certificatePEM, this._createdBy);
    return zipSync(files, { level: 6 });
  }

  /**
   * Build the archive and return it as a Blob (browser).
   * @returns {Blob}
   */
  toBlob() {
    const data = this.toUint8Array();
    return new Blob([data], { type: 'application/vnd.opa+zip' });
  }

  /**
   * Build the archive and return it as a Node.js Buffer.
   * @returns {Buffer}
   */
  toBuffer() {
    return Buffer.from(this.toUint8Array());
  }

  /**
   * Write the archive to a file (Node.js only).
   * @param {string} outputPath - Destination file path.
   */
  async writeToFile(outputPath) {
    const fs = await import('node:fs/promises');
    await fs.writeFile(outputPath, this.toUint8Array());
  }

  /**
   * Write a signed archive to a file (Node.js only).
   * @param {string} outputPath - Destination file path.
   * @param {string} privateKeyPEM - PEM-encoded private key.
   * @param {string} certificatePEM - PEM-encoded X.509 certificate.
   */
  async writeSignedToFile(outputPath, privateKeyPEM, certificatePEM) {
    const fs = await import('node:fs/promises');
    await fs.writeFile(outputPath, await this.toSignedUint8Array(privateKeyPEM, certificatePEM));
  }
}

/**
 * Verify a signed OPA archive.
 * @param {Uint8Array} data - The archive bytes.
 * @param {string} [certificatePEM] - PEM certificate to verify the signature against.
 *   If omitted, only digest integrity is checked.
 * @returns {Promise<{ valid: boolean, signed: boolean, error?: string }>}
 */
export async function verifyOpaArchive(data, certificatePEM) {
  const { unzipSync: unzip } = await import('fflate');
  const entries = unzip(data);
  return verifyArchive(entries, certificatePEM);
}
