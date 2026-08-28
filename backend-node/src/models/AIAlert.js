const mongoose = require('mongoose');

const AIAlertSchema = new mongoose.Schema({
  transfer_id: {
    type: mongoose.Schema.ObjectId,
    ref: 'Transfer'
  },
  user_id: {
    type: mongoose.Schema.ObjectId,
    ref: 'User'
  },
  level: {
    type: String,
    required: true
  },
  reason: {
    type: String,
    required: true
  },
  score: {
    type: Number,
    required: true
  },
  file_name: {
    type: String
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('AIAlert', AIAlertSchema);
