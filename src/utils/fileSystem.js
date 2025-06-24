const fs = require('fs').promises;
const path = require('path');
const logger = require('./logger');

/**
 * Create uploads directory if it doesn't exist
 */
const createUploadsDir = async () => {
  try {
    const uploadsPath = path.join(__dirname, '../../uploads');
    await fs.mkdir(uploadsPath, { recursive: true });
    logger.info('Uploads directory created/verified');
  } catch (error) {
    logger.error('Failed to create uploads directory:', error);
    throw error;
  }
};

/**
 * Create directory recursively
 * @param {string} dirPath - Directory path to create
 */
const createDirectory = async (dirPath) => {
  try {
    await fs.mkdir(dirPath, { recursive: true });
    return true;
  } catch (error) {
    logger.error(`Failed to create directory ${dirPath}:`, error);
    return false;
  }
};

/**
 * Check if file exists
 * @param {string} filePath - File path to check
 */
const fileExists = async (filePath) => {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
};

/**
 * Delete file safely
 * @param {string} filePath - File path to delete
 */
const deleteFile = async (filePath) => {
  try {
    if (await fileExists(filePath)) {
      await fs.unlink(filePath);
      logger.info(`File deleted: ${filePath}`);
      return true;
    }
    return false;
  } catch (error) {
    logger.error(`Failed to delete file ${filePath}:`, error);
    return false;
  }
};

/**
 * Get file stats
 * @param {string} filePath - File path to get stats for
 */
const getFileStats = async (filePath) => {
  try {
    const stats = await fs.stat(filePath);
    return {
      size: stats.size,
      created: stats.birthtime,
      modified: stats.mtime,
      isFile: stats.isFile(),
      isDirectory: stats.isDirectory()
    };
  } catch (error) {
    logger.error(`Failed to get file stats for ${filePath}:`, error);
    return null;
  }
};

/**
 * Clean up old files in directory
 * @param {string} dirPath - Directory path to clean
 * @param {number} maxAgeMs - Maximum age in milliseconds
 */
const cleanupOldFiles = async (dirPath, maxAgeMs = 24 * 60 * 60 * 1000) => {
  try {
    const files = await fs.readdir(dirPath);
    const now = Date.now();
    let deletedCount = 0;

    for (const file of files) {
      const filePath = path.join(dirPath, file);
      const stats = await getFileStats(filePath);
      
      if (stats && stats.isFile && (now - stats.modified.getTime()) > maxAgeMs) {
        if (await deleteFile(filePath)) {
          deletedCount++;
        }
      }
    }

    logger.info(`Cleaned up ${deletedCount} old files from ${dirPath}`);
    return deletedCount;
  } catch (error) {
    logger.error(`Failed to cleanup old files in ${dirPath}:`, error);
    return 0;
  }
};

/**
 * Get directory size
 * @param {string} dirPath - Directory path to calculate size for
 */
const getDirectorySize = async (dirPath) => {
  try {
    let totalSize = 0;
    const files = await fs.readdir(dirPath, { withFileTypes: true });

    for (const file of files) {
      const filePath = path.join(dirPath, file.name);
      
      if (file.isDirectory()) {
        totalSize += await getDirectorySize(filePath);
      } else {
        const stats = await fs.stat(filePath);
        totalSize += stats.size;
      }
    }

    return totalSize;
  } catch (error) {
    logger.error(`Failed to get directory size for ${dirPath}:`, error);
    return 0;
  }
};

/**
 * Format file size in human readable format
 * @param {number} bytes - Size in bytes
 */
const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Generate unique filename
 * @param {string} originalName - Original filename
 * @param {string} directory - Directory to check for conflicts
 */
const generateUniqueFilename = async (originalName, directory) => {
  const ext = path.extname(originalName);
  const name = path.basename(originalName, ext);
  let counter = 1;
  let newName = originalName;

  while (await fileExists(path.join(directory, newName))) {
    newName = `${name}_${counter}${ext}`;
    counter++;
  }

  return newName;
};

module.exports = {
  createUploadsDir,
  createDirectory,
  fileExists,
  deleteFile,
  getFileStats,
  cleanupOldFiles,
  getDirectorySize,
  formatFileSize,
  generateUniqueFilename
};
