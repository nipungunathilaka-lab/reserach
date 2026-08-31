const express = require('express');
const { protect, authorize } = require('../middleware/auth');
const User = require('../models/User');

const router = express.Router();

// Allow normal users to fetch a list of other users to send files to
router.get('/receivers', protect, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user._id } }).select('full_name email company_name');
    
    // Map _id to id for the frontend
    const mappedUsers = users.map(u => ({
      id: u._id.toString(),
      full_name: u.full_name,
      email: u.email,
      company_name: u.company_name
    }));

    res.status(200).json({ success: true, data: mappedUsers });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get('/', protect, authorize('admin'), async (req, res) => {
  try {
    const users = await User.find().select('-password_hash');
    res.status(200).json({ success: true, data: users });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
