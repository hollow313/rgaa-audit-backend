const zlib = require('node:zlib');

/**
 * Accepted top-level folder names for a plugin ZIP. The plugin was renamed to
 * "clairium-accessibility-audit" for wordpress.org; older archives are still
 * published under the previous slug, so both are accepted.
 * Override with PLUGIN_ROOT_SLUGS="slug-a,slug-b".
 *
 * @returns {string[]} Accepted root folder names
 */
function acceptedRootSlugs() {
  const raw = process.env.PLUGIN_ROOT_SLUGS;
  const list = (raw ? raw.split(',') : []).map((s) => s.trim()).filter(Boolean);
  return list.length ? list : ['clairium-accessibility-audit', 'rgaa-audit'];
}

/**
 * Reads one ZIP entry into a string.
 *
 * @param {Buffer} buf ZIP buffer
 * @param {{method:number, compSize:number, localHeaderOffset:number}} entry Entry info
 * @returns {string} File content
 */
function readEntry(buf, entry) {
  const { method, compSize, localHeaderOffset } = entry;

  if (localHeaderOffset + 30 > buf.length) {
    throw new Error('Local header offset out of bounds');
  }

  const lhFnLen = buf.readUInt16LE(localHeaderOffset + 26);
  const lhExtraLen = buf.readUInt16LE(localHeaderOffset + 28);
  const dataStart = localHeaderOffset + 30 + lhFnLen + lhExtraLen;
  const rawData = buf.subarray(dataStart, dataStart + compSize);

  if (method === 0) {
    return rawData.toString('utf8');
  }
  if (method === 8) {
    return zlib.inflateRawSync(rawData).toString('utf8');
  }

  throw new Error(`Compression method ${method} not supported`);
}

/**
 * Inspects a WordPress plugin zip buffer in memory.
 * Verifies that the archive holds a single accepted root folder and extracts
 * version info from the main PHP file (the one carrying a "Plugin Name:"
 * header) found at its root.
 *
 * @param {Buffer} buf Raw ZIP file buffer
 * @returns {object} { valid, zipVersion, requires, tested, requiresPhp, fileNames, error, message }
 */
function inspectPluginZip(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 22) {
    return { valid: false, error: 'invalid_zip', message: 'Payload is not a valid ZIP file' };
  }

  // Find End of Central Directory record (0x06054b50)
  let eocdOffset = -1;
  const maxSearch = Math.min(buf.length - 22, 65536 + 22);
  for (let i = buf.length - 22; i >= buf.length - 22 - maxSearch && i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset === -1) {
    return { valid: false, error: 'invalid_zip', message: 'EOCD signature not found in ZIP' };
  }

  const totalEntries = buf.readUInt16LE(eocdOffset + 10);
  const cdOffset = buf.readUInt32LE(eocdOffset + 16);

  if (cdOffset > buf.length) {
    return { valid: false, error: 'invalid_zip', message: 'Central directory offset out of bounds' };
  }

  let p = cdOffset;
  const fileNames = [];
  const rootPhpEntries = new Map();

  for (let i = 0; i < totalEntries && p < eocdOffset; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) {
      break;
    }

    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const fnLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localHeaderOffset = buf.readUInt32LE(p + 42);

    const fileNameRaw = buf.toString('utf8', p + 46, p + 46 + fnLen);
    const normalizedName = fileNameRaw.replace(/\\/g, '/');

    fileNames.push(normalizedName);

    if (/^[^/]+\/[^/]+\.php$/.test(normalizedName)) {
      rootPhpEntries.set(normalizedName, { method, compSize, localHeaderOffset });
    }

    p += 46 + fnLen + extraLen + commentLen;
  }

  // Root folder rule: exactly one top-level folder, and it must be an accepted
  // slug — this also rejects entries escaping the archive (zip-slip).
  const roots = new Set();
  for (const fn of fileNames) {
    if (!fn || fn === '/') continue;
    roots.add(fn.split('/')[0]);
  }

  const slugs = acceptedRootSlugs();
  if (roots.size !== 1) {
    return {
      valid: false,
      error: 'invalid_root_directory',
      message: `Expected a single root folder, found ${roots.size}: ${[...roots].join(', ')}`
    };
  }

  const root = [...roots][0];
  if (!slugs.includes(root)) {
    return {
      valid: false,
      error: 'invalid_root_directory',
      message: `Root folder '${root}' is not an accepted slug (${slugs.join(', ')})`
    };
  }

  // Main plugin file: <root>/<root>.php when present, otherwise the first
  // <root>/<name>.php carrying a "Plugin Name:" header.
  const mainCandidate = `${root}/${root}.php`;
  const candidates = [...rootPhpEntries.keys()]
    .filter((name) => name.startsWith(`${root}/`))
    .sort((a, b) => (a === mainCandidate ? -1 : 0) - (b === mainCandidate ? -1 : 0));

  let mainPhpContent = null;
  for (const name of candidates) {
    let content;
    try {
      content = readEntry(buf, rootPhpEntries.get(name));
    } catch (err) {
      return { valid: false, error: 'corrupt_zip_entry', message: err.message };
    }
    if (/Plugin Name:/i.test(content)) {
      mainPhpContent = content;
      break;
    }
  }

  if (!mainPhpContent) {
    return {
      valid: false,
      error: 'missing_main_file',
      message: `No PHP file with a Plugin Name header found in '${root}/'`
    };
  }

  // Extract metadata from main PHP file header
  const versionMatch = mainPhpContent.match(/Version:\s*([0-9A-Za-z.-]+)/i);
  const requiresMatch = mainPhpContent.match(/Requires at least:\s*([0-9A-Za-z.-]+)/i);
  const testedMatch = mainPhpContent.match(/Tested up to:\s*([0-9A-Za-z.-]+)/i);
  const phpMatch = mainPhpContent.match(/Requires PHP:\s*([0-9A-Za-z.-]+)/i);

  const zipVersion = versionMatch ? versionMatch[1].trim() : null;

  return {
    valid: true,
    zipVersion,
    requires: requiresMatch ? requiresMatch[1].trim() : null,
    tested: testedMatch ? testedMatch[1].trim() : null,
    requiresPhp: phpMatch ? phpMatch[1].trim() : null,
    fileNames
  };
}

module.exports = {
  inspectPluginZip
};
