const mongoose = require('mongoose');

const MfaChallengeSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  otp_hash: {
    type: String,
    required: true
  },
  expires_at: {
    type: Date,
    required: true
  },
  consumed_at: {
    type: Date
  },
  failed_attempts: {
    type: Number,
    default: 0
  },
  resend_count: {
    type: Number,
    default: 0
  },
  last_sent_at: {
    type: Date
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('MfaChallenge', MfaChallengeSchema);
