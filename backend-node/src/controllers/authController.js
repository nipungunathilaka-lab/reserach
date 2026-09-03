const User = require('../models/User');
const MfaChallenge = require('../models/MfaChallenge');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');

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

const sendMfaChallenge = async (user, res, statusCode, context = 'login') => {
  const crypto = require('crypto');
  const otp = crypto.randomInt ? crypto.randomInt(100000, 999999).toString() : Math.floor(100000 + Math.random() * 900000).toString();
  
  const salt = await bcrypt.genSalt(10);
  const otp_hash = await bcrypt.hash(otp, salt);
  
  const expires_at = new Date(Date.now() + 5 * 60 * 1000);

  await MfaChallenge.create({
    user_id: user._id,
    otp_hash,
    expires_at
  });

  const subject = context === 'register' ? 'Your Registration OTP' : 'Your Login OTP';
  
  try {
    await sendEmail({
      email: user.email,
      subject: subject,
      message: `Your One-Time Password for ${context} is: ${otp}. It is valid for 5 minutes.`,
      html: `<p>Your One-Time Password for ${context} is: <b>${otp}</b></p><p>It is valid for 5 minutes.</p>`
    });
    console.log(`[MFA] OTP sent to ${user.email}`);
  } catch (error) {
    console.error(`[MFA Error] Could not send email to ${user.email}:`, error);
    console.log(`[MFA Fallback] OTP for user ${user.email} is: ${otp}`);
  }

  res.status(statusCode).json({ 
    success: true, 
    mfaRequired: true, 
    user_id: user._id,
    challenge_id: user._id, // Add challenge_id for frontend compatibility
    message: `MFA challenge created. Please verify OTP.` 
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
    
    await sendMfaChallenge(user, res, 201, 'register');
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
    
    await sendMfaChallenge(user, res, 200, 'login');
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.verifyMfa = async (req, res) => {
  try {
    const { user_id, challenge_id, otp } = req.body;
    const uid = user_id || challenge_id;
    
    // The fast api expected challenge mapping. Let's assume we use challenge ID or email.
    // If they pass user_id or challenge_id, we can find the latest challenge.
    
    const challenge = await MfaChallenge.findOne({ user_id: uid }).sort({ created_at: -1 });
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
    
    const user = await User.findById(uid);
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
