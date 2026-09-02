const express = require('express');
const multer = require('multer');
const { sendFile, getReceivedFiles, downloadFile, uploadChunk, uploadStatus } = require('../controllers/fileController');
const { protect } = require('../middleware/auth');

const router = express.Router();
const upload = multer({ dest: 'uploads/' });

router.post('/send', protect, upload.single('file'), sendFile);
router.post('/upload-chunk', protect, upload.single('file'), uploadChunk);
router.get('/status/:id', protect, uploadStatus);
router.get('/received', protect, getReceivedFiles);
router.get('/:id/download', protect, downloadFile);

module.exports = router;
