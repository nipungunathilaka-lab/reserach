const express = require('express');
const multer = require('multer');
const { sendFile, getReceivedFiles, downloadFile } = require('../controllers/fileController');
const { protect } = require('../middleware/auth');

const router = express.Router();
const upload = multer({ dest: 'uploads/' });

router.post('/send', protect, upload.single('file'), sendFile);
router.get('/received', protect, getReceivedFiles);
router.get('/:id/download', protect, downloadFile);

module.exports = router;
