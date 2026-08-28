const mongoose = require('mongoose');

const BlockchainLogSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now
  },
  event_type: {
    type: String,
    required: true
  },
  details: {
    type: String,
    required: true
  },
  previous_hash: {
    type: String,
    required: true
  },
  block_hash: {
    type: String,
    required: true
  }
});

module.exports = mongoose.model('BlockchainLog', BlockchainLogSchema);
