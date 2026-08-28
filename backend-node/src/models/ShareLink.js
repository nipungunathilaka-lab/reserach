const mongoose = require('mongoose');

const ShareLinkSchema = new mongoose.Schema({
  transfer_id: {
    type: mongoose.Schema.ObjectId,
    ref: 'Transfer',
    required: true
  },
  link_token: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  expires_at: {
    type: Date,
    required: true
  },
  allowed_roles: {
    type: String
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('ShareLink', ShareLinkSchema);
