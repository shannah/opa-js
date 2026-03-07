/**
 * OPA archive signing and verification following the JAR signing convention.
 * Uses PKCS#7 (CMS) SignedData for signature blocks.
 * Node.js only — requires the built-in crypto module.
 */

// ── Helpers ─────────────────────────────────────────────────────────────

function concat(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function toBase64(data) {
  return Buffer.from(data).toString('base64');
}

function pemToDER(pem) {
  const b64 = pem.split('\n').filter(l => !l.startsWith('-----')).join('');
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

// ── Manifest line formatting (72-byte wrapping) ────────────────────────

function formatLine(name, value) {
  const line = `${name}: ${value}`;
  if (line.length <= 72) return line;
  const parts = [line.slice(0, 72)];
  let pos = 72;
  while (pos < line.length) {
    parts.push(' ' + line.slice(pos, pos + 71));
    pos += 71;
  }
  return parts.join('\r\n');
}

// ── DER Encoding ────────────────────────────────────────────────────────

function derLength(len) {
  if (len < 0x80) return new Uint8Array([len]);
  const bytes = [];
  let temp = len;
  while (temp > 0) {
    bytes.unshift(temp & 0xFF);
    temp >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function derEncode(tag, content) {
  const len = derLength(content.length);
  const result = new Uint8Array(1 + len.length + content.length);
  result[0] = tag;
  result.set(len, 1);
  result.set(content, 1 + len.length);
  return result;
}

function derSequence(...parts) { return derEncode(0x30, concat(...parts)); }
function derSet(...parts) { return derEncode(0x31, concat(...parts)); }
function derOctetString(data) { return derEncode(0x04, data); }
function derNull() { return new Uint8Array([0x05, 0x00]); }
function derOID(bytes) { return derEncode(0x06, new Uint8Array(bytes)); }
function derContextConstructed(tagNum, content) { return derEncode(0xA0 | tagNum, content); }

function derIntegerFromBigEndian(value) {
  // Strip leading zeros but keep at least one byte
  let start = 0;
  while (start < value.length - 1 && value[start] === 0 && !(value[start + 1] & 0x80)) {
    start++;
  }
  let bytes = value.slice(start);
  // Add leading zero if high bit set (to keep positive)
  if (bytes[0] & 0x80) {
    bytes = concat(new Uint8Array([0]), bytes);
  }
  return derEncode(0x02, bytes);
}

function derSmallInteger(n) {
  if (n <= 0x7F) return derEncode(0x02, new Uint8Array([n]));
  const bytes = [];
  let temp = n;
  while (temp > 0) {
    bytes.unshift(temp & 0xFF);
    temp >>>= 8;
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return derEncode(0x02, new Uint8Array(bytes));
}

// Precomputed OID byte sequences
const OID_SHA256             = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_RSA_ENCRYPTION     = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_SHA256_WITH_RSA    = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_SIGNED_DATA        = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_DATA               = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
const OID_ECDSA_WITH_SHA256  = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY      = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

function algorithmIdentifier(oidBytes) {
  return derSequence(derOID(oidBytes), derNull());
}

// ── DER Parsing ─────────────────────────────────────────────────────────

function parseTLV(data, offset = 0) {
  const tag = data[offset];
  let length, headerLen;
  if (data[offset + 1] < 0x80) {
    length = data[offset + 1];
    headerLen = 2;
  } else {
    const numBytes = data[offset + 1] & 0x7F;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length * 256) + data[offset + 2 + i];
    }
    headerLen = 2 + numBytes;
  }
  return { tag, valueOffset: offset + headerLen, length, end: offset + headerLen + length };
}

function getChildren(data, offset, end) {
  const children = [];
  let pos = offset;
  while (pos < end) {
    const tlv = parseTLV(data, pos);
    children.push({ ...tlv, raw: data.slice(pos, tlv.end) });
    pos = tlv.end;
  }
  return children;
}

// ── Certificate Parsing ─────────────────────────────────────────────────

function extractCertInfo(certDER) {
  const cert = parseTLV(certDER, 0);
  const certChildren = getChildren(certDER, cert.valueOffset, cert.end);
  // TBSCertificate is the first child
  const tbs = certChildren[0];
  const tbsChildren = getChildren(certDER, tbs.valueOffset, tbs.valueOffset + tbs.length);

  // If first child is context-tagged [0] (version), serial is at index 1, issuer at 3
  // Otherwise serial is at 0, issuer at 2
  const hasVersion = (tbsChildren[0].tag & 0xE0) === 0xA0;
  const serialIdx = hasVersion ? 1 : 0;
  const issuerIdx = hasVersion ? 3 : 2;

  return {
    issuerRaw: tbsChildren[issuerIdx].raw,
    serialRaw: tbsChildren[serialIdx].raw,
  };
}

// ── PKCS#7 SignedData Builder ───────────────────────────────────────────

function buildPKCS7SignedData(rawSignature, certDER, issuerRaw, serialRaw, isEC) {
  const digestAlgId = algorithmIdentifier(OID_SHA256);
  const sigAlgId = isEC
    ? derSequence(derOID(OID_ECDSA_WITH_SHA256))
    : algorithmIdentifier(OID_SHA256_WITH_RSA);

  const issuerAndSerial = derSequence(issuerRaw, serialRaw);

  const signerInfo = derSequence(
    derSmallInteger(1),      // version
    issuerAndSerial,
    digestAlgId,
    sigAlgId,
    derOctetString(rawSignature),
  );

  const signedData = derSequence(
    derSmallInteger(1),                           // version
    derSet(digestAlgId),                          // digestAlgorithms
    derSequence(derOID(OID_DATA)),                // encapContentInfo (detached)
    derContextConstructed(0, certDER),            // certificates [0] IMPLICIT
    derSet(signerInfo),                           // signerInfos
  );

  // Wrap in ContentInfo
  return derSequence(
    derOID(OID_SIGNED_DATA),
    derContextConstructed(0, signedData),
  );
}

// ── PKCS#7 Parsing (for verification) ───────────────────────────────────

function extractSignatureFromPKCS7(pkcs7DER) {
  // ContentInfo → [0] → SignedData → signerInfos → SignerInfo → signature
  const contentInfo = parseTLV(pkcs7DER, 0);
  const ciChildren = getChildren(pkcs7DER, contentInfo.valueOffset, contentInfo.end);

  // ciChildren[0] = OID (signedData), ciChildren[1] = [0] EXPLICIT content
  const explicit0 = ciChildren[1];
  const signedData = parseTLV(pkcs7DER, explicit0.valueOffset);
  const sdChildren = getChildren(pkcs7DER, signedData.valueOffset, signedData.end);

  // Find the last child which should be SET of SignerInfos
  const signerInfosSet = sdChildren[sdChildren.length - 1];
  const signerInfos = getChildren(pkcs7DER, signerInfosSet.valueOffset, signerInfosSet.valueOffset + signerInfosSet.length);

  // First (and only) SignerInfo
  const signerInfo = signerInfos[0];
  const siChildren = getChildren(pkcs7DER, signerInfo.valueOffset, signerInfo.valueOffset + signerInfo.length);

  // Last child of SignerInfo is the OCTET STRING signature
  const sigOctet = siChildren[siChildren.length - 1];
  return pkcs7DER.slice(sigOctet.valueOffset, sigOctet.valueOffset + sigOctet.length);
}

// ── Manifest Section Handling ───────────────────────────────────────────

/**
 * Build the per-entry manifest section for a file.
 * Returns the section string (without leading blank line, but with trailing \r\n).
 */
function buildEntrySection(name, sha256DigestBase64) {
  return formatLine('Name', name) + '\r\n'
    + formatLine('SHA-256-Digest', sha256DigestBase64) + '\r\n';
}

/**
 * Build SIGNATURE.SF content.
 * @param {Uint8Array} manifestBytes - The complete MANIFEST.MF content
 * @param {Array<{name: string, sectionText: string}>} entrySections - Per-entry sections
 * @param {function} sha256Fn - Synchronous SHA-256 function
 * @param {string} createdBy - Tool identifier
 * @returns {string}
 */
function buildSignatureFile(manifestBytes, entrySections, sha256Fn, createdBy) {
  const manifestDigest = toBase64(sha256Fn(manifestBytes));

  const lines = [];
  lines.push(formatLine('Signature-Version', '1.0'));
  lines.push(formatLine('Created-By', createdBy || 'opa-js'));
  lines.push(formatLine('SHA-256-Digest-Manifest', manifestDigest));

  let sf = lines.join('\r\n') + '\r\n';

  for (const entry of entrySections) {
    // Digest covers the section text including its trailing \r\n blank line
    const sectionBytes = Buffer.from(entry.sectionText, 'utf-8');
    const sectionDigest = toBase64(sha256Fn(sectionBytes));
    sf += '\r\n'; // blank line separating sections
    sf += formatLine('Name', entry.name) + '\r\n';
    sf += formatLine('SHA-256-Digest', sectionDigest) + '\r\n';
  }

  return sf;
}

// ── Signature File Parsing ──────────────────────────────────────────────

function parseSFSections(sfText) {
  // Split into sections by blank lines
  const rawSections = sfText.split(/\r?\n\r?\n/);
  const mainSection = {};
  const entrySections = [];

  for (let i = 0; i < rawSections.length; i++) {
    const section = rawSections[i].trim();
    if (!section) continue;

    const fields = {};
    let currentName = null;
    let currentValue = null;

    for (const line of section.split(/\r?\n/)) {
      if (line.startsWith(' ')) {
        // Continuation line
        if (currentName) currentValue += line.slice(1);
      } else {
        if (currentName) fields[currentName] = currentValue;
        const colonIdx = line.indexOf(':');
        if (colonIdx >= 0) {
          currentName = line.slice(0, colonIdx);
          currentValue = line.slice(colonIdx + 1).trimStart();
        }
      }
    }
    if (currentName) fields[currentName] = currentValue;

    if (i === 0 || !fields['Name']) {
      Object.assign(mainSection, fields);
    } else {
      entrySections.push(fields);
    }
  }

  return { mainSection, entrySections };
}

// ── Parse MANIFEST.MF into per-entry sections ──────────────────────────

function parseManifestEntrySections(manifestText) {
  // Parse line-by-line to correctly extract each entry section's text.
  // Each section starts with "Name:" and ends at a blank line or EOF.
  // Section text includes \r\n line endings matching what buildEntrySection produces.
  const sections = [];
  const lines = manifestText.split('\r\n');
  let currentSection = null;
  let currentName = null;
  let passedMainSection = false;

  for (const line of lines) {
    if (line === '') {
      // Blank line = section separator
      if (currentSection !== null && currentName !== null) {
        sections.push({ name: currentName, text: currentSection });
        currentSection = null;
        currentName = null;
      }
      passedMainSection = true;
      continue;
    }

    if (!passedMainSection) continue;

    if (line.startsWith('Name:')) {
      // Start of a new entry section
      if (currentSection !== null && currentName !== null) {
        sections.push({ name: currentName, text: currentSection });
      }
      currentName = line.slice(line.indexOf(':') + 1).trimStart();
      currentSection = line + '\r\n';
    } else if (currentSection !== null) {
      currentSection += line + '\r\n';
      // Handle continuation line for Name field
      if (line.startsWith(' ') && currentSection.split('\r\n').length === 3) {
        currentName += line.slice(1);
      }
    }
  }

  // Handle last section (may not have trailing blank line)
  if (currentSection !== null && currentName !== null) {
    sections.push({ name: currentName, text: currentSection });
  }

  return sections;
}

/** Parse manifest entry sections to extract Name → SHA-256-Digest mappings */
function parseManifestEntryDigests(manifestText) {
  const digests = new Map();
  const sections = parseManifestEntrySections(manifestText);
  for (const section of sections) {
    const digestMatch = section.text.match(/SHA-256-Digest:\s*(.+?)(?:\r?\n)/);
    if (digestMatch) {
      digests.set(section.name, digestMatch[1]);
    }
  }
  return digests;
}

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Sign an OPA archive. Adds MANIFEST.MF with per-entry digests,
 * SIGNATURE.SF, and the signature block file to the file map.
 *
 * @param {Object} files - Map of archive path → Uint8Array content
 * @param {string} mainManifestText - The main section of MANIFEST.MF (without entry sections)
 * @param {string} privateKeyPEM - PEM-encoded private key
 * @param {string} certificatePEM - PEM-encoded X.509 certificate
 * @param {string} [createdBy] - Tool identifier for SIGNATURE.SF
 * @returns {Object} Updated files map with signing artifacts added
 */
export async function signArchiveFiles(files, mainManifestText, privateKeyPEM, certificatePEM, createdBy) {
  const crypto = (await import('node:crypto')).default;
  const sha256Fn = (data) => new Uint8Array(crypto.createHash('sha256').update(data).digest());

  // Detect key type
  const privateKey = crypto.createPrivateKey(privateKeyPEM);
  const keyType = privateKey.asymmetricKeyType;
  if (keyType !== 'rsa' && keyType !== 'ec') {
    throw new Error(`Unsupported key type "${keyType}". Only RSA and EC keys are supported.`);
  }
  const isEC = keyType === 'ec';

  // Build per-entry manifest sections with SHA-256 digests of each file
  const entrySections = [];
  const fileEntries = Object.keys(files)
    .filter(p => p !== 'META-INF/MANIFEST.MF')
    .sort();

  for (const path of fileEntries) {
    const fileDigest = toBase64(sha256Fn(files[path]));
    const sectionText = buildEntrySection(path, fileDigest);
    entrySections.push({ name: path, sectionText });
  }

  // Build complete MANIFEST.MF: main section + blank line + entry sections
  let manifestText = mainManifestText;
  for (const entry of entrySections) {
    manifestText += '\r\n' + entry.sectionText;
  }

  const manifestBytes = Buffer.from(manifestText, 'utf-8');
  files['META-INF/MANIFEST.MF'] = new Uint8Array(manifestBytes);

  // Build SIGNATURE.SF
  const sfText = buildSignatureFile(manifestBytes, entrySections, sha256Fn, createdBy);
  const sfBytes = Buffer.from(sfText, 'utf-8');
  files['META-INF/SIGNATURE.SF'] = new Uint8Array(sfBytes);

  // Sign SIGNATURE.SF
  const rawSignature = crypto.sign('sha256', sfBytes, privateKey);

  // Build PKCS#7 SignedData
  const certDER = pemToDER(certificatePEM);
  const { issuerRaw, serialRaw } = extractCertInfo(certDER);
  const pkcs7 = buildPKCS7SignedData(
    new Uint8Array(rawSignature),
    certDER,
    issuerRaw,
    serialRaw,
    isEC,
  );

  const ext = isEC ? 'EC' : 'RSA';
  files[`META-INF/SIGNATURE.${ext}`] = pkcs7;

  return files;
}

/**
 * Verify a signed OPA archive.
 *
 * @param {Object} zipEntries - Map of archive path → Uint8Array content (from unzipSync)
 * @param {string} [certificatePEM] - Optional PEM certificate to verify against.
 *   If omitted, only digest integrity is checked (not the cryptographic signature).
 * @returns {{ valid: boolean, signed: boolean, error?: string }}
 */
export async function verifyArchive(zipEntries, certificatePEM) {
  const crypto = (await import('node:crypto')).default;
  const sha256Fn = (data) => new Uint8Array(crypto.createHash('sha256').update(data).digest());

  const sfEntry = zipEntries['META-INF/SIGNATURE.SF'];
  if (!sfEntry) {
    return { valid: true, signed: false };
  }

  // Find the signature block file
  let sigBlockPath = null;
  for (const ext of ['RSA', 'DSA', 'EC']) {
    const path = `META-INF/SIGNATURE.${ext}`;
    if (zipEntries[path]) {
      sigBlockPath = path;
      break;
    }
  }

  if (!sigBlockPath) {
    return { valid: false, signed: true, error: 'SIGNATURE.SF present but no signature block file (.RSA, .DSA, or .EC) found' };
  }

  const sfBytes = sfEntry;
  const sfText = Buffer.from(sfBytes).toString('utf-8');
  const { mainSection, entrySections } = parseSFSections(sfText);

  // 1. Verify cryptographic signature if certificate provided
  if (certificatePEM) {
    const sigBlockBytes = zipEntries[sigBlockPath];
    const rawSignature = extractSignatureFromPKCS7(sigBlockBytes);

    const isValid = crypto.verify(
      'sha256',
      sfBytes,
      certificatePEM,
      Buffer.from(rawSignature),
    );

    if (!isValid) {
      return { valid: false, signed: true, error: 'Digital signature verification failed' };
    }
  }

  // 2. Verify manifest digest
  const manifestBytes = zipEntries['META-INF/MANIFEST.MF'];
  if (!manifestBytes) {
    return { valid: false, signed: true, error: 'MANIFEST.MF not found' };
  }

  const manifestDigest = toBase64(sha256Fn(manifestBytes));
  const expectedManifestDigest = mainSection['SHA-256-Digest-Manifest'];
  if (manifestDigest !== expectedManifestDigest) {
    return { valid: false, signed: true, error: 'Manifest digest mismatch' };
  }

  // 3. Verify per-entry section digests in SIGNATURE.SF against MANIFEST.MF
  const manifestText = Buffer.from(manifestBytes).toString('utf-8');
  const mfEntrySections = parseManifestEntrySections(manifestText);

  for (const sfEntry of entrySections) {
    const name = sfEntry['Name'];
    const expectedDigest = sfEntry['SHA-256-Digest'];

    const mfSection = mfEntrySections.find(s => s.name === name);
    if (!mfSection) {
      return { valid: false, signed: true, error: `Manifest section not found for: ${name}` };
    }

    const sectionDigest = toBase64(sha256Fn(Buffer.from(mfSection.text, 'utf-8')));
    if (sectionDigest !== expectedDigest) {
      return { valid: false, signed: true, error: `Section digest mismatch for: ${name}` };
    }
  }

  // 4. Verify actual file contents match digests in MANIFEST.MF
  const mfDigests = parseManifestEntryDigests(manifestText);
  for (const [name, expectedDigest] of mfDigests) {
    const fileData = zipEntries[name];
    if (!fileData) {
      return { valid: false, signed: true, error: `File missing from archive: ${name}` };
    }
    const actualDigest = toBase64(sha256Fn(fileData));
    if (actualDigest !== expectedDigest) {
      return { valid: false, signed: true, error: `File content digest mismatch for: ${name}` };
    }
  }

  return { valid: true, signed: true };
}
