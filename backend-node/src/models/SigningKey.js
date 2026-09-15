const mongoose = require('mongoose');

const SigningKeySchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  algorithm: {
    type: String,
    required: true,
    default: 'RSA-PSS-SHA256'
  },
  public_key_spki: {
    type: String, // Base64 encoded SPKI
    required: true
  },
  public_key_fingerprint: {
    type: String, // SHA-256 hex string
    required: true,
    unique: true
  },
  key_version: {
    type: Number,
    default: 1
  },
  status: {
    type: String,
    enum: ['ACTIVE', 'REVOKED', 'SUPERSEDED'],
    default: 'ACTIVE'
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  revoked_at: {
    type: Date
  },
  proof_of_possession_verified: {
    type: Boolean,
    default: false
  }
});

module.exports = mongoose.model('SigningKey', SigningKeySchema);
