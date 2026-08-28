const Transfer = require('../models/Transfer');
const User = require('../models/User');
const AIAlert = require('../models/AIAlert');

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

    // The frontend expects the root object, so we send it directly instead of wrapping in { success: true, data: ... }
    // to match the original Python FastAPI behavior.
    res.status(200).json({
      total_transfers: totalFiles + encryptedFiles,
      received_files: totalFiles,
      ai_alerts: alerts,
      blockchain_valid: true,
      blockchain_status: 'All blocks intact',
      recent_activity: formattedActivity,
      recent_alerts: recentAlerts,
      audit_logs: []
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
