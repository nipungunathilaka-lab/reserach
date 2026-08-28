const mongoose = require('mongoose');

const AuditBlockSchema = new mongoose.Schema({
  event_type: {
    type: String,
    required: true
  },
  details_json: {
    type: String,
    required: true
  },
  previous_hash: {
    type: String,
    required: true
  },
  block_hash: {
    type: String,
    required: true,
    unique: true
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('AuditBlock', AuditBlockSchema);
