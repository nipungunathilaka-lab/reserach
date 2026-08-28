const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  full_name: {
    type: String,
    required: true,
    maxlength: 120
  },
  email: {
    type: String,
    required: true,
    unique: true,
    index: true,
    maxlength: 255
  },
  password_hash: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  company_name: {
    type: String,
    maxlength: 255
  },
  job_role: {
    type: String,
    maxlength: 100
  },
  mfa_enabled: {
    type: Boolean,
    default: true
  },
  totp_secret: {
    type: String,
    maxlength: 255
  },
  failed_login_attempts: {
    type: Number,
    default: 0
  },
  locked_until: {
    type: Date
  },
  last_login_at: {
    type: Date
  },
  last_login_ip: {
    type: String,
    maxlength: 80
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('User', UserSchema);
