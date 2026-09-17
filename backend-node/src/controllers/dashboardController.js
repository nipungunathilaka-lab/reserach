const Transfer = require('../models/Transfer');
const User = require('../models/User');
const AIAlert = require('../models/AIAlert');
const axios = require('axios');
const { getInternalServiceToken } = require('../utils/internalAuth');

exports.getDashboardStats = async (req, res) => {
  try {
    const totalFiles = await Transfer.countDocuments({ receiver_id: req.user._id });
    const encryptedFiles = await Transfer.countDocuments({ receiver_id: req.user._id, status: 'encrypted' });
    const alerts = await AIAlert.countDocuments({ user_id: req.user._id });
    const recentTransfers = await Transfer.find({ $or: [{ sender_id: req.user._id }, { receiver_id: req.user._id }] })
      .sort({ created_at: -1 })
      .limit(5)
      .populate('sender_id', 'full_name')
      .populate('receiver_id', 'full_name');
      
    const recentAlerts = await AIAlert.find({ user_id: req.user._id }).sort({ created_at: -1 }).limit(5);

    // Format transfers to match frontend expectation (sender.full_name)
    const formattedActivity = recentTransfers.map(t => ({
      id: t._id,
      file_name: t.file_name,
      sender: { full_name: t.sender_id?.full_name || 'Unknown' },
      receiver: { full_name: t.receiver_id?.full_name || 'Unknown' },
      status: t.status
    }));

    // Call Python Internal Engine to verify authoritative ledger
    let blockchain_valid = false;
    let blockchain_status = 'VERIFICATION_ERROR';
    let blockchain_message = 'Unable to verify ledger integrity';
    let checked_records = 0;
    let verified_at = null;
    let invalid_record_id = null;
    let invalid_sequence = null;
    let verification_reason = 'API_ERROR';

    const pythonUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
    try {
      const verifyRes = await axios.get(`${pythonUrl}/internal/audit/verify-ledger`, {
        headers: { Authorization: `Bearer ${getInternalServiceToken('GET', '/internal/audit/verify-ledger')}` }
      });
      if (verifyRes.data) {
        blockchain_valid = verifyRes.data.valid;
        blockchain_status = verifyRes.data.status;
        blockchain_message = verifyRes.data.message;
        checked_records = verifyRes.data.checked_records;
        verified_at = verifyRes.data.verified_at;
        invalid_record_id = verifyRes.data.invalid_record_id;
        invalid_sequence = verifyRes.data.invalid_sequence;
        verification_reason = verifyRes.data.reason;
      }
    } catch (pythonErr) {
      console.error('Python Verification Error:', pythonErr.message);
    }

    // The frontend expects the root object, so we send it directly instead of wrapping in { success: true, data: ... }
    res.status(200).json({
      total_transfers: totalFiles + encryptedFiles,
      received_files: totalFiles,
      ai_alerts: alerts,
      blockchain_valid: blockchain_valid,
      blockchain_status: blockchain_status,
      blockchain_message: blockchain_message,
      blockchain_checked_records: checked_records,
      blockchain_verified_at: verified_at,
      blockchain_invalid_record_id: invalid_record_id,
      blockchain_invalid_sequence: invalid_sequence,
      blockchain_reason: verification_reason,
      recent_activity: formattedActivity,
      recent_alerts: recentAlerts,
      audit_logs: []
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
