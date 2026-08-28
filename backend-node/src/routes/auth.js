const express = require('express');
const { register, login, getMe, verifyMfa } = require('../controllers/authController');
const { protect } = require('../middleware/auth');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/verify-mfa', verifyMfa);
router.get('/me', protect, getMe);

module.exports = router;
