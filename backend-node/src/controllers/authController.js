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
  // 1. Strictly use cryptographically secure generator
  const otp = crypto.randomInt(100000, 999999).toString();
  
  const salt = await bcrypt.genSalt(10);
  const otp_hash = await bcrypt.hash(otp, salt);
  
  // 2. Use configured expiry
  const expireMinutes = parseInt(process.env.MFA_OTP_EXPIRE_MINUTES || 5, 10);
  const expires_at = new Date(Date.now() + expireMinutes * 60 * 1000);

  const challenge = await MfaChallenge.create({
    user_id: user._id,
    otp_hash,
    expires_at,
    last_sent_at: new Date(),
    resend_count: 0
  });

  const subject = context === 'register' ? 'Your Registration OTP' : 'Your Login OTP';
  
  try {
    await sendEmail({
      email: user.email,
      subject: subject,
      message: `Your One-Time Password for ${context} is: ${otp}. It is valid for ${expireMinutes} minutes.`,
      html: `<p>Your One-Time Password for ${context} is: <b>${otp}</b></p><p>It is valid for ${expireMinutes} minutes.</p>`
    });
    console.log(`[MFA] OTP sent to ${user.email}`);
  } catch (error) {
    console.error(`[MFA Error] Could not send email to ${user.email}:`, error);
    if (process.env.DEV_SHOW_OTP === 'true') {
      console.log(`[MFA Fallback] OTP for user ${user.email} is: ${otp}`);
    } else {
      // 3. Fail closed if email delivery fails
      return res.status(500).json({ success: false, error: 'MFA email delivery failed. Please try again.' });
    }
  }

  res.status(statusCode).json({ 
    success: true, 
    mfaRequired: true, 
    user_id: user._id,
    challenge_id: challenge._id,
    dev_otp: process.env.DEV_SHOW_OTP === 'true' ? otp : undefined,
    masked_email: user.email.replace(/(.{2})(.*)(?=@)/, (gp1, gp2, gp3) => gp2 + '*'.repeat(gp3.length)),
    expires_in: expireMinutes * 60,
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
    
    // Use the actual challenge_id if provided
    const query = challenge_id ? { _id: challenge_id } : { user_id: uid };
    const challenge = await MfaChallenge.findOne(query).sort({ created_at: -1 });
    
    if (!challenge) {
      return res.status(400).json({ success: false, error: 'Invalid MFA challenge' });
    }
    
    if (challenge.consumed_at) {
      return res.status(400).json({ success: false, error: 'MFA challenge already consumed' });
    }

    if (new Date() > challenge.expires_at) {
      return res.status(400).json({ success: false, error: 'MFA code expired. Please log in again.' });
    }

    const maxAttempts = parseInt(process.env.MFA_MAX_ATTEMPTS || 5, 10);
    if (challenge.failed_attempts >= maxAttempts) {
      challenge.consumed_at = new Date();
      await challenge.save();
      return res.status(429).json({ success: false, error: 'Too many incorrect MFA attempts. Please log in again.' });
    }
    
    const isMatch = await bcrypt.compare(otp, challenge.otp_hash);
    if (!isMatch) {
      challenge.failed_attempts += 1;
      const remaining = maxAttempts - challenge.failed_attempts;
      
      if (challenge.failed_attempts >= maxAttempts) {
        challenge.consumed_at = new Date();
        await challenge.save();
        return res.status(429).json({ success: false, error: 'Too many incorrect MFA attempts. Please log in again.' });
      } else {
        await challenge.save();
        return res.status(401).json({ success: false, error: `Invalid MFA code. ${remaining} attempt(s) remaining.` });
      }
    }
    
    challenge.consumed_at = new Date();
    await challenge.save();
    
    const user = await User.findById(challenge.user_id);
    sendTokenResponse(user, 200, res);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.resendMfa = async (req, res) => {
  try {
    const { challenge_id } = req.body;
    if (!challenge_id) return res.status(400).json({ success: false, error: 'Challenge ID is required' });

    const challenge = await MfaChallenge.findById(challenge_id);
    if (!challenge) return res.status(400).json({ success: false, error: 'Invalid MFA challenge' });
    if (challenge.consumed_at) return res.status(400).json({ success: false, error: 'MFA challenge already consumed' });
    if (new Date() > challenge.expires_at) return res.status(400).json({ success: false, error: 'MFA code expired. Please log in again.' });

    const maxResends = parseInt(process.env.MFA_MAX_RESENDS || 3, 10);
    if (challenge.resend_count >= maxResends) {
      return res.status(429).json({ success: false, error: 'Maximum MFA resend limit reached. Please log in again.' });
    }

    const cooldown = parseInt(process.env.MFA_RESEND_COOLDOWN_SECONDS || 60, 10);
    if (challenge.last_sent_at) {
      const secondsSince = (Date.now() - challenge.last_sent_at.getTime()) / 1000;
      if (secondsSince < cooldown) {
        const wait = Math.max(1, Math.ceil(cooldown - secondsSince));
        return res.status(429).json({ success: false, error: `Please wait ${wait} second(s) before resending.` });
      }
    }

    // Invalidate old challenge
    challenge.consumed_at = new Date();
    await challenge.save();

    // Create a new challenge
    const user = await User.findById(challenge.user_id);
    const crypto = require('crypto');
    const otp = crypto.randomInt(100000, 999999).toString();
    const salt = await bcrypt.genSalt(10);
    const otp_hash = await bcrypt.hash(otp, salt);
    
    const expireMinutes = parseInt(process.env.MFA_OTP_EXPIRE_MINUTES || 5, 10);
    const expires_at = new Date(Date.now() + expireMinutes * 60 * 1000);

    const newChallenge = await MfaChallenge.create({
      user_id: user._id,
      otp_hash,
      expires_at,
      last_sent_at: new Date(),
      resend_count: challenge.resend_count + 1
    });

    try {
      await sendEmail({
        email: user.email,
        subject: 'Your New Login OTP',
        message: `Your new One-Time Password is: ${otp}. It is valid for ${expireMinutes} minutes.`,
        html: `<p>Your new One-Time Password is: <b>${otp}</b></p><p>It is valid for ${expireMinutes} minutes.</p>`
      });
      console.log(`[MFA] Resend OTP sent to ${user.email}`);
    } catch (error) {
      console.error(`[MFA Error] Could not send email to ${user.email}:`, error);
      if (process.env.DEV_SHOW_OTP === 'true') {
        console.log(`[MFA Fallback] OTP for user ${user.email} is: ${otp}`);
      } else {
        return res.status(500).json({ success: false, error: 'MFA email delivery failed. Please try again.' });
      }
    }

    res.status(200).json({
      success: true,
      mfaRequired: true,
      user_id: user._id,
      challenge_id: newChallenge._id,
      dev_otp: process.env.DEV_SHOW_OTP === 'true' ? otp : undefined,
      masked_email: user.email.replace(/(.{2})(.*)(?=@)/, (gp1, gp2, gp3) => gp2 + '*'.repeat(gp3.length)),
      expires_in: expireMinutes * 60,
      message: `New MFA challenge created. Please verify OTP.`
    });
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
