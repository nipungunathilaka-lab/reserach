const express = require('express');
const { register, login, getMe, verifyMfa, resendMfa } = require('../controllers/authController');
const { protect } = require('../middleware/auth');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/verify-mfa', verifyMfa);
router.post('/resend-mfa', resendMfa);
router.get('/me', protect, getMe);

module.exports = router;
