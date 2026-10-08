const express = require('express');
const axios = require('axios');
const FormData = require('form-data');
const { getInternalServiceToken } = require('../utils/internalAuth');
const { protect } = require('../middleware/auth');
const cryptoController = require('../controllers/cryptoController');

const router = express.Router();

router.post('/ecdh/exchange', protect, async (req, res) => {
  try {
    const formData = new FormData();
    formData.append('user_id', String(req.user.id));
    
    const serviceToken = getInternalServiceToken('POST', '/internal/crypto/ensure_keys');
    
    const pyRes = await axios.post(`${process.env.PYTHON_SERVICE_URL}/internal/crypto/ensure_keys`, formData, {
        headers: {
            ...formData.getHeaders(),
            'Authorization': `Bearer ${serviceToken}`
        }
    });

    res.status(200).json({ 
        success: true, 
        data: {
            message: 'Secure session established',
            server_public_key_pem: pyRes.data.server_public_key_pem
        }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/register-key-challenge', protect, cryptoController.registerKeyChallenge);
router.post('/register-key', protect, cryptoController.registerKey);
router.post('/transfer-challenge', protect, cryptoController.transferChallenge);
router.get('/key-status', protect, cryptoController.checkKeyStatus);

module.exports = router;
