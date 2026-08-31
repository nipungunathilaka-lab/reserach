const Transfer = require('../models/Transfer');
const User = require('../models/User');
const AIAlert = require('../models/AIAlert');
const AuditBlock = require('../models/AuditBlock');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const crypto = require('crypto');

exports.sendFile = async (req, res) => {
  try {
    const { receiver_id, classification } = req.body;
    const file = req.file;

    if (!file || !receiver_id) {
      return res.status(400).json({ success: false, error: 'File and receiver_id are required' });
    }

    const receiver = await User.findById(receiver_id);
    if (!receiver) {
      return res.status(404).json({ success: false, error: 'Receiver not found' });
    }

    // Prepare form data to send to Python microservice
    const formData = new FormData();
    formData.append('file', fs.createReadStream(file.path), file.originalname);
    formData.append('sender_id', req.user._id.toString());
    formData.append('receiver_id', receiver._id.toString());
    formData.append('classification', classification || 'standard');
    // Align with Python AI detection fields to prevent 422 Unprocessable Entity
    formData.append('transfers_last_hour', '0');
    formData.append('mfa_failed_attempts', '0');
    formData.append('failed_login_attempts', req.user.failed_login_attempts?.toString() || '0');

    // Call Python Internal Engine
    const pythonUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
    let response;
    try {
      response = await axios.post(`${pythonUrl}/internal/crypto/encrypt`, formData, {
        headers: {
          ...formData.getHeaders()
        }
      });
    } catch (pythonErr) {
      console.error('Python Encrypt Error:', pythonErr.response?.data || pythonErr.message);
      return res.status(pythonErr.response?.status || 500).json({ success: false, error: 'Internal Engine Encryption Failed' });
    }

    const pythonData = response.data;

    // Save transfer in Mongo
    const transfer = await Transfer.create({
      file_name: file.originalname,
      stored_name: pythonData.stored_name,
      file_group_id: crypto.randomBytes(16).toString('hex'),
      original_hash: pythonData.original_hash,
      encrypted_path: pythonData.encrypted_path,
      encrypted_key: pythonData.encrypted_key,
      nonce: pythonData.nonce,
      ecdh_public_key: pythonData.ecdh_public_key,
      ecdh_wrapped_key: pythonData.ecdh_wrapped_key,
      file_size: file.size,
      sender_id: req.user._id,
      receiver_id: receiver._id,
      status: 'encrypted',
      integrity_status: 'pending_download',
      anomaly_score: pythonData.anomaly_score,
      is_anomaly: pythonData.is_anomaly,
      anomaly_level: pythonData.anomaly_level,
      anomaly_reason: pythonData.anomaly_reason
    });

    // Cleanup local temp file
    fs.unlinkSync(file.path);

    res.status(200).json({
      success: true,
      data: transfer
    });
  } catch (err) {
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.getReceivedFiles = async (req, res) => {
  try {
    const transfers = await Transfer.find({ receiver_id: req.user._id }).populate('sender_id', 'email full_name');
    res.status(200).json({ success: true, data: transfers });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.downloadFile = async (req, res) => {
  try {
    const transfer = await Transfer.findById(req.params.id);
    if (!transfer) {
      return res.status(404).json({ success: false, error: 'Transfer not found' });
    }

    if (transfer.receiver_id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'Not authorized' });
    }

    // Forward to Python microservice to decapsulate and decrypt using JSON matching Pydantic schema
    const pythonUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
    let response;
    try {
      response = await axios.post(`${pythonUrl}/internal/crypto/decrypt`, {
        encrypted_path: transfer.encrypted_path,
        receiver_id: req.user._id.toString()
      }, {
        responseType: 'stream'
      });
    } catch (pythonErr) {
      console.error('Python Decrypt Error:', pythonErr.response?.data || pythonErr.message);
      return res.status(pythonErr.response?.status || 500).json({ success: false, error: 'Internal Engine Decryption Failed' });
    }

    res.setHeader('Content-Disposition', `attachment; filename="${transfer.file_name}"`);
    response.data.pipe(res);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
