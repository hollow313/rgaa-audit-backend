const zlib = require('node:zlib');

/**
 * Inspects a WordPress plugin zip buffer in memory.
 * Verifies that the root folder is 'rgaa-audit' and extracts version info
 * from 'rgaa-audit/rgaa-audit.php'.
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
  let mainPhpContent = null;

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

    if (normalizedName === 'rgaa-audit/rgaa-audit.php') {
      if (localHeaderOffset + 30 > buf.length) {
        return { valid: false, error: 'invalid_zip', message: 'Local header offset out of bounds' };
      }
      const lhFnLen = buf.readUInt16LE(localHeaderOffset + 26);
      const lhExtraLen = buf.readUInt16LE(localHeaderOffset + 28);
      const dataStart = localHeaderOffset + 30 + lhFnLen + lhExtraLen;
      const rawData = buf.subarray(dataStart, dataStart + compSize);

      try {
        if (method === 0) {
          mainPhpContent = rawData.toString('utf8');
        } else if (method === 8) {
          mainPhpContent = zlib.inflateRawSync(rawData).toString('utf8');
        } else {
          return { valid: false, error: 'unsupported_compression', message: `Compression method ${method} not supported` };
        }
      } catch (err) {
        return { valid: false, error: 'corrupt_zip_entry', message: err.message };
      }
    }

    p += 46 + fnLen + extraLen + commentLen;
  }

  // Check root folder rule: every entry must be 'rgaa-audit' or start with 'rgaa-audit/'
  for (const fn of fileNames) {
    if (!fn || fn === '/') continue;
    if (fn !== 'rgaa-audit' && !fn.startsWith('rgaa-audit/')) {
      return {
        valid: false,
        error: 'invalid_root_directory',
        message: `Entry '${fn}' is not inside root folder 'rgaa-audit'`
      };
    }
  }

  if (!mainPhpContent) {
    return {
      valid: false,
      error: 'missing_main_file',
      message: 'rgaa-audit/rgaa-audit.php not found in zip archive'
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
