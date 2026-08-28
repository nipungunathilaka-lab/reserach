const User = require('../models/User');
const MfaChallenge = require('../models/MfaChallenge');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const sendTokenResponse = (user, statusCode, res) => {
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE
  });
  res.status(statusCode).json({
    success: true,
    access_token: token,
    token_type: 'bearer',
    user: {
      id: user._id,
      email: user.email,
      full_name: user.full_name,
      role: user.role
    }
  });
};

exports.register = async (req, res) => {
  try {
    const { full_name, email, password, role, company_name, job_role } = req.body;
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ success: false, error: 'Email already registered' });
    }
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);
    
    // Map frontend roles ('manager' etc) to valid DB enum if necessary
    const validRole = role === 'admin' ? 'admin' : 'user';

    const user = await User.create({
      full_name,
      email,
      password_hash,
      role: validRole,
      company_name,
      job_role
    });
    
    sendTokenResponse(user, 201, res);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Please provide email and password' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    // Deactivated MFA for now: immediately issue token
    sendTokenResponse(user, 200, res);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.verifyMfa = async (req, res) => {
  try {
    const { user_id, otp } = req.body;
    // user_id in the original request might actually be email or challenge_id.
    // The fast api expected challenge mapping. Let's assume we use challenge ID or email.
    // If they pass user_id, we can find the latest challenge.
    
    const challenge = await MfaChallenge.findOne({ user_id }).sort({ created_at: -1 });
    if (!challenge || challenge.consumed_at || new Date() > challenge.expires_at) {
      return res.status(400).json({ success: false, error: 'Invalid or expired OTP' });
    }
    
    const isMatch = await bcrypt.compare(otp, challenge.otp_hash);
    if (!isMatch) {
      challenge.failed_attempts += 1;
      await challenge.save();
      return res.status(400).json({ success: false, error: 'Invalid OTP' });
    }
    
    challenge.consumed_at = new Date();
    await challenge.save();
    
    const user = await User.findById(user_id);
    sendTokenResponse(user, 200, res);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.getMe = async (req, res) => {
  res.status(200).json({
    success: true,
    data: req.user
  });
};
