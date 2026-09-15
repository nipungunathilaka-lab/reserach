const express = require('express');
const { protect } = require('../middleware/auth');
const cryptoController = require('../controllers/cryptoController');

const router = express.Router();

router.post('/ecdh/exchange', protect, (req, res) => {
  res.status(200).json({ success: true, message: 'Secure session established' });
});

router.post('/register-key-challenge', protect, cryptoController.registerKeyChallenge);
router.post('/register-key', protect, cryptoController.registerKey);
router.post('/transfer-challenge', protect, cryptoController.transferChallenge);
router.get('/key-status', protect, cryptoController.checkKeyStatus);

module.exports = router;
