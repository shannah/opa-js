/**
 * Browser-compatible OPA archive signing using Web Crypto API.
 * Uses ECDSA P-256 with SHA-256 and non-extractable private keys.
 * Also works in Node.js 19+ via globalThis.crypto.subtle.
 *
 * Self-contained module — duplicates some DER/manifest helpers from
 * signing.js to avoid depending on Node.js-specific code.
 */

// ── Helpers ─────────────────────────────────────────────────────────────

function concat(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { result.set(a, offset); offset += a.length; }
  return result;
}

function toBase64(data) {
  let binary = '';
  for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
  return btoa(binary);
}

const textEncode = (str) => new TextEncoder().encode(str);
const textDecode = (bytes) => new TextDecoder().decode(bytes);

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

// ── DER Encoding ────────────────────────────────────────────────────────

function derLength(len) {
  if (len < 0x80) return new Uint8Array([len]);
  const bytes = [];
  let temp = len;
  while (temp > 0) { bytes.unshift(temp & 0xFF); temp >>>= 8; }
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
function derUTF8String(str) { return derEncode(0x0C, textEncode(str)); }
function derBitString(data) { return derEncode(0x03, concat(new Uint8Array([0x00]), data)); }

function derUTCTime(date) {
  const pad = n => String(n).padStart(2, '0');
  const str = pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) + pad(date.getUTCDate()) +
    pad(date.getUTCHours()) + pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) + 'Z';
  return derEncode(0x17, textEncode(str));
}

function derSmallInteger(n) {
  if (n <= 0x7F) return derEncode(0x02, new Uint8Array([n]));
  const bytes = [];
  let temp = n;
  while (temp > 0) { bytes.unshift(temp & 0xFF); temp >>>= 8; }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return derEncode(0x02, new Uint8Array(bytes));
}

// Precomputed OID byte sequences
const OID_SHA256            = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_ECDSA_WITH_SHA256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_SIGNED_DATA       = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_DATA              = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
const OID_COMMON_NAME       = [0x55, 0x04, 0x03];

function sha256AlgId() { return derSequence(derOID(OID_SHA256), derNull()); }
// ECDSA algorithm identifiers omit the parameters field (RFC 5758)
function ecdsaSHA256AlgId() { return derSequence(derOID(OID_ECDSA_WITH_SHA256)); }

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
    for (let i = 0; i < numBytes; i++) length = (length * 256) + data[offset + 2 + i];
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

// ── Certificate Info Extraction ─────────────────────────────────────────

function extractCertInfo(certDER) {
  const cert = parseTLV(certDER, 0);
  const certChildren = getChildren(certDER, cert.valueOffset, cert.end);
  const tbs = certChildren[0];
  const tbsChildren = getChildren(certDER, tbs.valueOffset, tbs.valueOffset + tbs.length);
  const hasVersion = (tbsChildren[0].tag & 0xE0) === 0xA0;
  const serialIdx = hasVersion ? 1 : 0;
  const issuerIdx = hasVersion ? 3 : 2;
  const spkiIdx = hasVersion ? 6 : 5;
  return {
    issuerRaw: tbsChildren[issuerIdx].raw,
    serialRaw: tbsChildren[serialIdx].raw,
    spkiRaw: tbsChildren[spkiIdx].raw,
  };
}

// ── ECDSA Signature Format Conversion ───────────────────────────────────

/** Convert IEEE P1363 (r||s) to DER (SEQUENCE { INTEGER r, INTEGER s }) */
function p1363ToDER(sig) {
  const half = sig.length / 2;
  const r = sig.slice(0, half);
  const s = sig.slice(half);

  function intBytes(v) {
    let start = 0;
    while (start < v.length - 1 && v[start] === 0 && !(v[start + 1] & 0x80)) start++;
    let bytes = v.slice(start);
    if (bytes[0] & 0x80) bytes = concat(new Uint8Array([0]), bytes);
    return bytes;
  }

  return derSequence(
    derEncode(0x02, intBytes(r)),
    derEncode(0x02, intBytes(s)),
  );
}

/** Convert DER (SEQUENCE { INTEGER r, INTEGER s }) to IEEE P1363 (r||s) */
function derToP1363(sig, keySize) {
  const seq = parseTLV(sig, 0);
  const children = getChildren(sig, seq.valueOffset, seq.end);
  const r = sig.slice(children[0].valueOffset, children[0].valueOffset + children[0].length);
  const s = sig.slice(children[1].valueOffset, children[1].valueOffset + children[1].length);

  function padTo(arr, len) {
    if (arr.length === len) return arr;
    if (arr.length > len) return arr.slice(arr.length - len);
    const padded = new Uint8Array(len);
    padded.set(arr, len - arr.length);
    return padded;
  }

  return concat(padTo(r, keySize), padTo(s, keySize));
}

// ── X.509 Self-Signed Certificate Builder ───────────────────────────────

function buildX509Name(cn) {
  return derSequence(
    derSet(
      derSequence(
        derOID(OID_COMMON_NAME),
        derUTF8String(cn),
      ),
    ),
  );
}

async function buildSelfSignedCert(privateKey, publicKey, cn) {
  const spkiDER = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));

  const now = new Date();
  const later = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  const name = buildX509Name(cn);
  const algId = ecdsaSHA256AlgId();

  const tbsCert = derSequence(
    derContextConstructed(0, derSmallInteger(2)),    // version v3
    derSmallInteger(1),                              // serialNumber
    algId,                                           // signature algorithm
    name,                                            // issuer
    derSequence(derUTCTime(now), derUTCTime(later)),  // validity
    name,                                            // subject (same = self-signed)
    spkiDER,                                         // subjectPublicKeyInfo
  );

  // Sign the TBSCertificate
  const sigP1363 = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    tbsCert,
  ));
  const sigDER = p1363ToDER(sigP1363);

  return derSequence(
    tbsCert,
    algId,
    derBitString(sigDER),
  );
}

// ── PKCS#7 SignedData ───────────────────────────────────────────────────

function buildPKCS7SignedData(rawSignatureDER, certDER, issuerRaw, serialRaw) {
  const digestAlgId = sha256AlgId();
  const sigAlgId = ecdsaSHA256AlgId();

  const signerInfo = derSequence(
    derSmallInteger(1),
    derSequence(issuerRaw, serialRaw),
    digestAlgId,
    sigAlgId,
    derOctetString(rawSignatureDER),
  );

  const signedData = derSequence(
    derSmallInteger(1),
    derSet(digestAlgId),
    derSequence(derOID(OID_DATA)),
    derContextConstructed(0, certDER),
    derSet(signerInfo),
  );

  return derSequence(
    derOID(OID_SIGNED_DATA),
    derContextConstructed(0, signedData),
  );
}

function extractSignatureFromPKCS7(pkcs7DER) {
  const contentInfo = parseTLV(pkcs7DER, 0);
  const ciChildren = getChildren(pkcs7DER, contentInfo.valueOffset, contentInfo.end);
  const explicit0 = ciChildren[1];
  const signedData = parseTLV(pkcs7DER, explicit0.valueOffset);
  const sdChildren = getChildren(pkcs7DER, signedData.valueOffset, signedData.end);
  const signerInfosSet = sdChildren[sdChildren.length - 1];
  const signerInfos = getChildren(pkcs7DER, signerInfosSet.valueOffset,
    signerInfosSet.valueOffset + signerInfosSet.length);
  const signerInfo = signerInfos[0];
  const siChildren = getChildren(pkcs7DER, signerInfo.valueOffset,
    signerInfo.valueOffset + signerInfo.length);
  const sigOctet = siChildren[siChildren.length - 1];
  return pkcs7DER.slice(sigOctet.valueOffset, sigOctet.valueOffset + sigOctet.length);
}

/** Extract the first certificate DER from a PKCS#7 SignedData structure. */
export function extractCertFromPKCS7(pkcs7DER) {
  const contentInfo = parseTLV(pkcs7DER, 0);
  const ciChildren = getChildren(pkcs7DER, contentInfo.valueOffset, contentInfo.end);
  const explicit0 = ciChildren[1];
  const signedData = parseTLV(pkcs7DER, explicit0.valueOffset);
  const sdChildren = getChildren(pkcs7DER, signedData.valueOffset, signedData.end);

  // certificates field is [0] IMPLICIT, tag 0xA0
  for (const child of sdChildren) {
    if (child.tag === 0xA0) {
      const certTLV = parseTLV(pkcs7DER, child.valueOffset);
      return pkcs7DER.slice(child.valueOffset, certTLV.end);
    }
  }
  return null;
}

// ── Manifest / Signature File Helpers ───────────────────────────────────

function formatLine(name, value) {
  const line = `${name}: ${value}`;
  if (line.length <= 72) return line;
  const parts = [line.slice(0, 72)];
  let pos = 72;
  while (pos < line.length) { parts.push(' ' + line.slice(pos, pos + 71)); pos += 71; }
  return parts.join('\r\n');
}

function buildEntrySection(name, digestBase64) {
  return formatLine('Name', name) + '\r\n'
    + formatLine('SHA-256-Digest', digestBase64) + '\r\n';
}

async function buildSignatureFile(manifestBytes, entrySections, createdBy) {
  const manifestDigest = toBase64(await sha256(manifestBytes));
  const lines = [];
  lines.push(formatLine('Signature-Version', '1.0'));
  lines.push(formatLine('Created-By', createdBy || 'opa-js'));
  lines.push(formatLine('SHA-256-Digest-Manifest', manifestDigest));
  let sf = lines.join('\r\n') + '\r\n';

  for (const entry of entrySections) {
    const sectionDigest = toBase64(await sha256(textEncode(entry.sectionText)));
    sf += '\r\n' + formatLine('Name', entry.name) + '\r\n';
    sf += formatLine('SHA-256-Digest', sectionDigest) + '\r\n';
  }
  return sf;
}

function parseSFSections(sfText) {
  const rawSections = sfText.split(/\r?\n\r?\n/);
  const mainSection = {};
  const entrySections = [];
  for (let i = 0; i < rawSections.length; i++) {
    const section = rawSections[i].trim();
    if (!section) continue;
    const fields = {};
    let currentName = null, currentValue = null;
    for (const line of section.split(/\r?\n/)) {
      if (line.startsWith(' ')) {
        if (currentName) currentValue += line.slice(1);
      } else {
        if (currentName) fields[currentName] = currentValue;
        const ci = line.indexOf(':');
        if (ci >= 0) { currentName = line.slice(0, ci); currentValue = line.slice(ci + 1).trimStart(); }
      }
    }
    if (currentName) fields[currentName] = currentValue;
    if (i === 0 || !fields['Name']) Object.assign(mainSection, fields);
    else entrySections.push(fields);
  }
  return { mainSection, entrySections };
}

function parseManifestEntrySections(manifestText) {
  const sections = [];
  const lines = manifestText.split('\r\n');
  let currentSection = null, currentName = null, passedMainSection = false;
  for (const line of lines) {
    if (line === '') {
      if (currentSection !== null && currentName !== null) {
        sections.push({ name: currentName, text: currentSection });
        currentSection = null; currentName = null;
      }
      passedMainSection = true;
      continue;
    }
    if (!passedMainSection) continue;
    if (line.startsWith('Name:')) {
      if (currentSection !== null && currentName !== null) {
        sections.push({ name: currentName, text: currentSection });
      }
      currentName = line.slice(line.indexOf(':') + 1).trimStart();
      currentSection = line + '\r\n';
    } else if (currentSection !== null) {
      currentSection += line + '\r\n';
      if (line.startsWith(' ') && currentSection.split('\r\n').length === 3) {
        currentName += line.slice(1);
      }
    }
  }
  if (currentSection !== null && currentName !== null) {
    sections.push({ name: currentName, text: currentSection });
  }
  return sections;
}

function parseManifestEntryDigests(manifestText) {
  const digests = new Map();
  for (const section of parseManifestEntrySections(manifestText)) {
    const m = section.text.match(/SHA-256-Digest:\s*(.+?)(?:\r?\n)/);
    if (m) digests.set(section.name, m[1]);
  }
  return digests;
}

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Generate an ECDSA P-256 key pair for browser signing.
 * The private key is non-extractable (cannot be read by JavaScript).
 * The public key is extractable (can be exported for certificates and fingerprints).
 * Store both keys in IndexedDB for persistence across sessions.
 *
 * @returns {Promise<{ privateKey: CryptoKey, publicKey: CryptoKey }>}
 */
export async function generateSigningKey() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // non-extractable private key
    ['sign', 'verify'],
  );
  return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
}

/**
 * Compute a SHA-256 fingerprint of a public key.
 * Returns a string like "sha256:a3f8b2c1...".
 *
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function getPublicKeyFingerprint(publicKey) {
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
  const hash = await sha256(spki);
  return 'sha256:' + Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Sign an OPA archive using the Web Crypto API (browser or Node.js 19+).
 * Builds a self-signed X.509 certificate from the key pair and produces
 * JAR-compatible SIGNATURE.SF + SIGNATURE.EC files.
 *
 * @param {Object} files - Map of archive path → Uint8Array
 * @param {string} mainManifestText - Main section of MANIFEST.MF
 * @param {CryptoKey} privateKey - ECDSA P-256 private key
 * @param {CryptoKey} publicKey - ECDSA P-256 public key
 * @param {string} [createdBy] - Tool identifier for SIGNATURE.SF
 */
export async function signArchiveFilesBrowser(files, mainManifestText, privateKey, publicKey, createdBy) {
  // Build self-signed certificate
  const fingerprint = await getPublicKeyFingerprint(publicKey);
  const cn = 'OPA Browser Key ' + fingerprint.slice(7, 23);
  const certDER = await buildSelfSignedCert(privateKey, publicKey, cn);
  const { issuerRaw, serialRaw } = extractCertInfo(certDER);

  // Build per-entry manifest sections with SHA-256 digests
  const entrySections = [];
  const fileEntries = Object.keys(files).filter(p => p !== 'META-INF/MANIFEST.MF').sort();
  for (const path of fileEntries) {
    const fileDigest = toBase64(await sha256(files[path]));
    entrySections.push({ name: path, sectionText: buildEntrySection(path, fileDigest) });
  }

  // Build complete MANIFEST.MF
  let manifestText = mainManifestText;
  for (const entry of entrySections) manifestText += '\r\n' + entry.sectionText;
  const manifestBytes = textEncode(manifestText);
  files['META-INF/MANIFEST.MF'] = manifestBytes;

  // Build SIGNATURE.SF
  const sfText = await buildSignatureFile(manifestBytes, entrySections, createdBy);
  const sfBytes = textEncode(sfText);
  files['META-INF/SIGNATURE.SF'] = sfBytes;

  // Sign SIGNATURE.SF with ECDSA
  const sigP1363 = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    sfBytes,
  ));
  const sigDER = p1363ToDER(sigP1363);

  // Build PKCS#7 SignedData
  const pkcs7 = buildPKCS7SignedData(sigDER, certDER, issuerRaw, serialRaw);
  files['META-INF/SIGNATURE.EC'] = pkcs7;

  return files;
}

/**
 * Verify a signed OPA archive using the Web Crypto API.
 * Works with both EC-signed (browser) and RSA-signed (Node.js) archives.
 *
 * If no public key is provided, the certificate is extracted from the
 * PKCS#7 signature block and used for verification. The result includes
 * a publicKeyFingerprint for trust-on-first-use (TOFU) decisions.
 *
 * @param {Object} zipEntries - Map of archive path → Uint8Array (from unzipSync)
 * @param {CryptoKey} [publicKey] - Optional public key to verify against
 * @returns {Promise<{ valid: boolean, signed: boolean, error?: string, publicKeyFingerprint?: string }>}
 */
export async function verifyArchiveBrowser(zipEntries, publicKey) {
  const sfEntry = zipEntries['META-INF/SIGNATURE.SF'];
  if (!sfEntry) return { valid: true, signed: false };

  // Find the signature block file
  let sigBlockPath = null;
  for (const ext of ['RSA', 'DSA', 'EC']) {
    if (zipEntries[`META-INF/SIGNATURE.${ext}`]) {
      sigBlockPath = `META-INF/SIGNATURE.${ext}`;
      break;
    }
  }
  if (!sigBlockPath) {
    return { valid: false, signed: true, error: 'No signature block file found' };
  }

  const sfBytes = sfEntry;
  const sfText = textDecode(sfBytes);
  const { mainSection, entrySections } = parseSFSections(sfText);
  const isEC = sigBlockPath.endsWith('.EC');

  let verifyKey = publicKey;
  let fingerprint = null;

  // If no public key provided, extract from the embedded certificate
  if (!verifyKey) {
    const sigBlockBytes = zipEntries[sigBlockPath];
    const certDER = extractCertFromPKCS7(sigBlockBytes);
    if (!certDER) {
      return { valid: false, signed: true, error: 'Could not extract certificate from signature block' };
    }

    const { spkiRaw } = extractCertInfo(certDER);
    const algorithm = isEC
      ? { name: 'ECDSA', namedCurve: 'P-256' }
      : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };

    verifyKey = await crypto.subtle.importKey('spki', spkiRaw, algorithm, true, ['verify']);

    const hash = await sha256(spkiRaw);
    fingerprint = 'sha256:' + Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  } else if (verifyKey instanceof CryptoKey) {
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', verifyKey));
    const hash = await sha256(spki);
    fingerprint = 'sha256:' + Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // 1. Verify digital signature
  const rawSigDER = extractSignatureFromPKCS7(zipEntries[sigBlockPath]);

  let isValid;
  if (isEC) {
    const sigP1363 = derToP1363(rawSigDER, 32);
    isValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, verifyKey, sigP1363, sfBytes,
    );
  } else {
    isValid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', verifyKey, rawSigDER, sfBytes,
    );
  }
  if (!isValid) {
    return { valid: false, signed: true, error: 'Digital signature verification failed' };
  }

  // 2. Verify manifest digest
  const manifestBytes = zipEntries['META-INF/MANIFEST.MF'];
  if (!manifestBytes) return { valid: false, signed: true, error: 'MANIFEST.MF not found' };

  const manifestDigest = toBase64(await sha256(manifestBytes));
  if (manifestDigest !== mainSection['SHA-256-Digest-Manifest']) {
    return { valid: false, signed: true, error: 'Manifest digest mismatch' };
  }

  // 3. Verify per-entry section digests
  const manifestText = textDecode(manifestBytes);
  const mfEntrySections = parseManifestEntrySections(manifestText);
  for (const sfEntry of entrySections) {
    const name = sfEntry['Name'];
    const mfSection = mfEntrySections.find(s => s.name === name);
    if (!mfSection) {
      return { valid: false, signed: true, error: `Manifest section not found for: ${name}` };
    }
    const sectionDigest = toBase64(await sha256(textEncode(mfSection.text)));
    if (sectionDigest !== sfEntry['SHA-256-Digest']) {
      return { valid: false, signed: true, error: `Section digest mismatch for: ${name}` };
    }
  }

  // 4. Verify file contents match manifest digests
  const mfDigests = parseManifestEntryDigests(manifestText);
  for (const [name, expectedDigest] of mfDigests) {
    const fileData = zipEntries[name];
    if (!fileData) return { valid: false, signed: true, error: `File missing: ${name}` };
    if (toBase64(await sha256(fileData)) !== expectedDigest) {
      return { valid: false, signed: true, error: `File digest mismatch for: ${name}` };
    }
  }

  const result = { valid: true, signed: true };
  if (fingerprint) result.publicKeyFingerprint = fingerprint;
  return result;
}
