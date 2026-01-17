const cron = require('node-cron');
const fs = require('fs').promises;
const path = require('path');
const logger = require('../utils/logger');
const { deleteFile, fileExists, getFileStats } = require('../utils/fileSystem');

/**
 * Clean up expired reverse image search uploads
 * This runs every hour to delete images older than 24 hours
 */
class ImageCleanupService {
  constructor() {
    this.isRunning = false;
    this.cronJob = null;
    this.uploadsDir = path.join(__dirname, '../../uploads/reverse-search');
  }

  /**
   * Start the cleanup service
   */
  start() {
    // Schedule cleanup to run every hour
    this.cronJob = cron.schedule('0 * * * *', async () => {
      await this.cleanup();
    });

    logger.info('Image cleanup service started (runs hourly)');

    // Run initial cleanup on startup
    setTimeout(() => {
      this.cleanup();
    }, 5000); // Wait 5 seconds after startup
  }

  /**
   * Stop the cleanup service
   */
  stop() {
    if (this.cronJob) {
      this.cronJob.stop();
      logger.info('Image cleanup service stopped');
    }
  }

  /**
   * Perform cleanup of expired images
   */
  async cleanup() {
    if (this.isRunning) {
      logger.info('Cleanup already in progress, skipping...');
      return;
    }

    this.isRunning = true;
    const startTime = Date.now();

    try {
      logger.info('Starting reverse image search cleanup');

      // Check if directory exists
      try {
        await fs.access(this.uploadsDir);
      } catch (error) {
        logger.info('Uploads directory does not exist yet, skipping cleanup');
        this.isRunning = false;
        return;
      }

      // Get all files in the directory
      const files = await fs.readdir(this.uploadsDir);

      if (files.length === 0) {
        logger.info('No files to clean up');
        this.isRunning = false;
        return;
      }

      const now = Date.now();
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
      let deletedCount = 0;
      let errorCount = 0;
      let totalSize = 0;

      for (const file of files) {
        try {
          const filePath = path.join(this.uploadsDir, file);
          const stats = await getFileStats(filePath);

          if (!stats || !stats.isFile) {
            continue;
          }

          // Check if file is older than 24 hours
          const fileAge = now - stats.modified.getTime();

          if (fileAge > maxAge) {
            totalSize += stats.size;
            await deleteFile(filePath);
            deletedCount++;

            // If this is a .jpg file, also delete the corresponding .json metadata
            if (file.endsWith('.jpg')) {
              const metadataFile = file.replace('.jpg', '.json');
              const metadataPath = path.join(this.uploadsDir, metadataFile);

              if (await fileExists(metadataPath)) {
                await deleteFile(metadataPath);
              }
            }

            logger.info('Deleted expired image', {
              filename: file,
              age: Math.round(fileAge / 1000 / 60 / 60) + ' hours',
              size: stats.size
            });
          }
        } catch (error) {
          errorCount++;
          logger.error('Error processing file during cleanup', {
            file,
            error: error.message
          });
        }
      }

      const duration = Date.now() - startTime;

      logger.info('Reverse image search cleanup completed', {
        duration: duration + 'ms',
        totalFiles: files.length,
        deletedCount,
        errorCount,
        freedSpace: this.formatBytes(totalSize)
      });

    } catch (error) {
      logger.error('Cleanup service error:', {
        error: error.message,
        stack: error.stack
      });
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Format bytes to human readable format
   * @param {number} bytes - Size in bytes
   * @returns {string} Formatted size
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Get statistics about current uploads
   * @returns {object} Statistics
   */
  async getStats() {
    try {
      await fs.access(this.uploadsDir);
      const files = await fs.readdir(this.uploadsDir);

      // Filter to only .jpg files (not metadata)
      const imageFiles = files.filter(f => f.endsWith('.jpg'));

      let totalSize = 0;
      let oldestFile = null;
      let newestFile = null;

      for (const file of imageFiles) {
        const filePath = path.join(this.uploadsDir, file);
        const stats = await getFileStats(filePath);

        if (stats && stats.isFile) {
          totalSize += stats.size;

          if (!oldestFile || stats.created < oldestFile.created) {
            oldestFile = { name: file, ...stats };
          }

          if (!newestFile || stats.created > newestFile.created) {
            newestFile = { name: file, ...stats };
          }
        }
      }

      return {
        totalImages: imageFiles.length,
        totalSize: this.formatBytes(totalSize),
        totalSizeBytes: totalSize,
        oldestFile: oldestFile ? {
          name: oldestFile.name,
          age: Math.round((Date.now() - oldestFile.created.getTime()) / 1000 / 60) + ' minutes'
        } : null,
        newestFile: newestFile ? {
          name: newestFile.name,
          age: Math.round((Date.now() - newestFile.created.getTime()) / 1000 / 60) + ' minutes'
        } : null
      };
    } catch (error) {
      logger.error('Error getting cleanup stats:', error);
      return {
        totalImages: 0,
        totalSize: '0 Bytes',
        error: error.message
      };
    }
  }

  /**
   * Manually trigger cleanup (for testing or admin purposes)
   */
  async manualCleanup() {
    logger.info('Manual cleanup triggered');
    await this.cleanup();
  }
}

// Create singleton instance
const imageCleanupService = new ImageCleanupService();

module.exports = imageCleanupService;
