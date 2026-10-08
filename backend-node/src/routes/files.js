const express = require('express');
const { sendFile, getReceivedFiles, getSentFiles, downloadFile, uploadChunk, uploadStatus, createShareLink, releaseQuarantinedFile } = require('../controllers/fileController');
const { protect } = require('../middleware/auth');

const router = express.Router();
const path = require('path');

// Multer and MemoryStorage removed completely to enforce strict streaming.
// File streaming is now handled directly via busboy in the controller.

router.post('/send', protect, sendFile);
router.post('/upload-chunk', protect, uploadChunk);
router.get('/status/:id', protect, uploadStatus);
router.get('/received', protect, getReceivedFiles);
router.get('/sent', protect, getSentFiles);
router.get('/:id/download', protect, downloadFile);
router.post('/:id/share', protect, createShareLink);
router.post('/:id/release', protect, releaseQuarantinedFile);

module.exports = router;
