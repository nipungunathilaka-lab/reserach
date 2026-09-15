const mongoose = require('mongoose');

const SigningChallengeSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  nonce: {
    type: String,
    required: true,
    unique: true
  },
  purpose: {
    type: String,
    enum: ['REGISTRATION', 'TRANSFER_SIGNING'],
    required: true
  },
  consumed: {
    type: Boolean,
    default: false
  },
  expires_at: {
    type: Date,
    required: true
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

// TTL index to automatically delete expired challenges
SigningChallengeSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('SigningChallenge', SigningChallengeSchema);
