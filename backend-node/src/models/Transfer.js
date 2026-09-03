const mongoose = require('mongoose');

const TransferSchema = new mongoose.Schema({
  file_name: {
    type: String,
    required: true
  },
  stored_name: {
    type: String,
    required: true
  },
  version: {
    type: Number,
    default: 1
  },
  file_group_id: {
    type: String,
    required: true
  },
  original_hash: {
    type: String,
    required: true
  },
  decrypted_hash: {
    type: String
  },
  encrypted_path: {
    type: String,
    required: true
  },
  decrypted_path: {
    type: String
  },
  encrypted_key: {
    type: String,
    required: true
  },
  nonce: {
    type: String,
    required: true
  },
  ecdh_public_key: {
    type: String
  },
  ecdh_wrapped_key: {
    type: String
  },
  ecdh_key_nonce: {
    type: String
  },
  file_size: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    default: 'encrypted'
  },
  integrity_status: {
    type: String,
    default: 'pending_download'
  },
  cipher_algorithm: {
    type: String
  },
  anomaly_score: {
    type: Number
  },
  is_anomaly: {
    type: Boolean,
    default: false
  },
  anomaly_reason: {
    type: String
  },
  anomaly_level: {
    type: String
  },
  transfers_last_hour: {
    type: Number,
    default: 0
  },
  mfa_failed_attempts: {
    type: Number,
    default: 0
  },
  high_risk_file_type: {
    type: Boolean,
    default: false
  },
  sender_failed_login_attempts: {
    type: Number,
    default: 0
  },
  sender_id: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  receiver_id: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  share_token: {
    type: String,
    unique: true,
    sparse: true
  },
  share_pin: {
    type: String
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Transfer', TransferSchema);
