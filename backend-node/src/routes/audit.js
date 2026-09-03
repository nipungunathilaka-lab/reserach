const express = require('express');
const { protect } = require('../middleware/auth');
const BlockchainLog = require('../models/BlockchainLog');
const AIAlert = require('../models/AIAlert');

const router = express.Router();
const Transfer = require('../models/Transfer');

router.get('/transfers', protect, async (req, res) => {
  try {
    const logs = await Transfer.find()
      .populate('sender_id', 'email full_name')
      .populate('receiver_id', 'email full_name')
      .sort({ created_at: -1 });
    res.status(200).json({ success: true, data: logs });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get('/blockchain', protect, async (req, res) => {
  try {
    const logs = await BlockchainLog.find().sort({ timestamp: -1 });
    res.status(200).json({ success: true, data: logs });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get('/ai-alerts', protect, async (req, res) => {
  try {
    const alerts = await AIAlert.find().sort({ created_at: -1 }).populate('user_id', 'email full_name');
    res.status(200).json({ success: true, data: alerts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
