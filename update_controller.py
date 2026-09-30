import re

with open('backend-node/src/controllers/fileController.js', 'r', encoding='utf-8') as f:
    code = f.read()

# Add Busboy import at the top
code = code.replace("const fs = require('fs');", "const fs = require('fs');\nconst Busboy = require('busboy');")

new_send_file = '''exports.sendFile = async (req, res) => {
  const busboy = Busboy({ headers: req.headers });
  const fields = {};
  let pythonPromise = null;
  let fileProcessed = false;

  busboy.on('field', (fieldname, val) => {
    fields[fieldname] = val;
  });

  busboy.on('file', (fieldname, file, info) => {
    fileProcessed = true;
    pythonPromise = (async () => {
      try {
        await new Promise(r => setTimeout(r, 100)); // allow fields to parse
        const { receiver_id, classification } = fields;
        if (!receiver_id) throw new Error('receiver_id is required before file in FormData');

        const receiver = await User.findById(receiver_id);
        if (!receiver) throw new Error('Receiver not found');

        const hourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const transfers_last_hour = await Transfer.countDocuments({ sender_id: req.user._id, created_at: { $gte: hourAgo } });
        
        const recentChallenges = await MfaChallenge.find({ user_id: req.user._id, created_at: { $gte: hourAgo } });
        const mfa_failed_attempts = recentChallenges.reduce((sum, c) => sum + (c.failed_attempts || 0), 0);

        const formData = new FormData();
        formData.append('file', file, info.filename);
        formData.append('sender_id', req.user._id.toString());
        formData.append('receiver_id', receiver._id.toString());
        formData.append('classification', classification || 'standard');
        formData.append('transfers_last_hour', transfers_last_hour.toString());
        formData.append('mfa_failed_attempts', mfa_failed_attempts.toString());
        formData.append('failed_login_attempts', req.user.failed_login_attempts?.toString() || '0');

        const pythonUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
        
        const response = await axios.post(`${pythonUrl}/internal/crypto/encrypt`, formData, {
          headers: {
            ...formData.getHeaders(),
            'Authorization': `Bearer ${getInternalServiceToken('POST', '/internal/crypto/encrypt')}`,
            'X-Benchmark-Test-Mode': req.headers['x-benchmark-test-mode'] || 'false'
          },
          maxBodyLength: Infinity,
          maxContentLength: Infinity
        });
        
        return { pythonData: response.data, receiver, filename: info.filename };
      } catch (err) {
        file.resume(); // consume remaining stream
        throw err;
      }
    })();
  });

  busboy.on('close', async () => {
    try {
      if (!fileProcessed) {
        return res.status(400).json({ success: false, error: 'File is required' });
      }
      const { pythonData, receiver, filename } = await pythonPromise;

      const transfer = await Transfer.create({
        file_name: filename,
        stored_name: pythonData.stored_name,
        file_group_id: crypto.randomBytes(16).toString('hex'),
        original_hash: pythonData.original_hash,
        encrypted_path: pythonData.encrypted_path,
        encrypted_key: pythonData.encrypted_key,
        nonce: pythonData.nonce,
        ecdh_public_key: pythonData.ecdh_public_key,
        ecdh_wrapped_key: pythonData.ecdh_wrapped_key,
        file_size: pythonData.file_size_bytes || 0,
        sender_id: req.user._id,
        receiver_id: receiver._id,
        status: 'encrypted',
        integrity_status: 'pending_download',
        anomaly_score: pythonData.anomaly_score,
        is_anomaly: pythonData.is_anomaly,
        anomaly_level: pythonData.anomaly_level,
        anomaly_reason: pythonData.anomaly_reason,
        cipher_algorithm: pythonData.cipher_algorithm
      });

      const block = await appendToBlockchain('FILE_TRANSFER', {
        transfer_id: transfer._id,
        sender: req.user.email,
        receiver: receiver.email,
        file_size: transfer.file_size,
        classification: fields.classification || 'standard',
        ai_score: pythonData.anomaly_score,
        network_score: pythonData.network_risk_score,
        combined_score: pythonData.combined_risk_score
      });

      res.status(200).json({ success: true, data: transfer });
    } catch (err) {
      if (err.response?.status === 406) {
        const detail = err.response?.data?.detail;
        const reasonMsg = typeof detail === 'object' ? detail.message : detail;
        const threatScore = (detail && typeof detail === 'object' && detail.anomaly_score !== undefined) ? detail.anomaly_score : 1.0;

        await appendToBlockchain('MALWARE_BLOCKED', {
          sender_id: req.user._id,
          file_name: 'unknown',
          reason: reasonMsg
        });
        
        await AIAlert.create({
          user_id: req.user._id,
          level: 'critical',
          reason: reasonMsg || 'Malware detected',
          score: threatScore,
          file_name: 'unknown'
        });
      }
      res.status(err.response?.status || 500).json({ success: false, error: err.response?.data?.detail || err.message });
    }
  });

  req.pipe(busboy);
};'''

new_upload_chunk = '''exports.uploadChunk = async (req, res) => {
  const busboy = Busboy({ headers: req.headers });
  const fields = {};
  let tempFilePath = null;
  let filename = '';

  busboy.on('field', (fieldname, val) => {
    fields[fieldname] = val;
  });

  busboy.on('file', (fieldname, file, info) => {
    tempFilePath = path.join(os.tmpdir(), `chunk_${Date.now()}_${Math.random()}`);
    filename = info.filename;
    const writeStream = fs.createWriteStream(tempFilePath);
    file.pipe(writeStream);
  });

  busboy.on('close', async () => {
    try {
      if (!tempFilePath) {
        return res.status(400).json({ success: false, error: 'File chunk is required' });
      }

      const receiver_id = fields.receiver_id;
      const upload_id = fields.upload_id;
      const chunk_index = parseInt(fields.chunk_index);
      const total_chunks = parseInt(fields.total_chunks);
      const file_name = fields.file_name;

      const receiver = await User.findById(receiver_id);
      if (!receiver) {
        safeUnlink(tempFilePath);
        return res.status(404).json({ success: false, error: 'Receiver not found' });
      }

      const tempDir = path.join(os.tmpdir(), 'secure_transfer_chunks');
      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
      }
      const assembledFilePath = path.join(tempDir, `${upload_id}_${file_name}`);

      await new Promise((resolve, reject) => {
        const readStream = fs.createReadStream(tempFilePath);
        const writeStream = fs.createWriteStream(assembledFilePath, { flags: 'a' });
        readStream.on('error', reject);
        writeStream.on('error', reject);
        writeStream.on('finish', resolve);
        readStream.pipe(writeStream);
      });
      
      safeUnlink(tempFilePath);

      if (chunk_index < total_chunks - 1) {
        return res.status(200).json({ status: 'chunk_received', chunk_index });
      }

      UPLOAD_STATUSES[upload_id] = { status: 'processing', message: 'File assembled, encrypting...' };
      res.status(200).json({ status: 'processing', message: 'File assembling and encrypting...' });

      // Background processing
      setImmediate(async () => {
        try {
          const hourAgo = new Date(Date.now() - 60 * 60 * 1000);
          const transfers_last_hour = await Transfer.countDocuments({ sender_id: req.user._id, created_at: { $gte: hourAgo } });
          
          const recentChallenges = await MfaChallenge.find({ user_id: req.user._id, created_at: { $gte: hourAgo } });
          const mfa_failed_attempts = recentChallenges.reduce((sum, c) => sum + (c.failed_attempts || 0), 0);

          const formData = new FormData();
          const assembledFileSize = fs.statSync(assembledFilePath).size;
          formData.append('file', fs.createReadStream(assembledFilePath), file_name);
          formData.append('sender_id', req.user._id.toString());
          formData.append('receiver_id', receiver._id.toString());
          formData.append('classification', 'standard');
          formData.append('transfers_last_hour', transfers_last_hour.toString());
          formData.append('mfa_failed_attempts', mfa_failed_attempts.toString());
          formData.append('failed_login_attempts', req.user.failed_login_attempts?.toString() || '0');

          if (!fields.client_signature) {
            safeUnlink(assembledFilePath);
            UPLOAD_STATUSES[upload_id] = { status: 'error', message: 'Digital signature is required for all file transfers.' };
            return;
          }

          formData.append('transfer_id', upload_id);
          formData.append('client_signature', fields.client_signature);
          formData.append('signed_payload_version', fields.signed_payload_version || 'UPCE-TRANSFER-SIGNATURE-V1');
          formData.append('client_nonce', fields.client_nonce || '');
          formData.append('original_file_sha256', fields.original_file_sha256 || '');
          formData.append('issued_at', fields.issued_at || '');

          const signingKey = await SigningKey.findOne({ user_id: req.user._id, status: 'ACTIVE' });
          if (signingKey) {
            formData.append('sender_public_key_spki', signingKey.public_key_spki);
          } else {
            formData.append('sender_public_key_spki', '');
          }

          const pythonUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
          const pythonResponse = await axios.post(`${pythonUrl}/internal/crypto/encrypt`, formData, {
            headers: {
              ...formData.getHeaders(),
              'Authorization': `Bearer ${getInternalServiceToken('POST', '/internal/crypto/encrypt')}`,
              'X-Benchmark-Test-Mode': req.headers['x-benchmark-test-mode'] || 'false'
            },
            maxBodyLength: Infinity,
            maxContentLength: Infinity
          });

          const pythonData = pythonResponse.data;

          if (fields.client_signature && fields.client_nonce) {
            await SigningChallenge.findOneAndUpdate(
              { user_id: req.user._id, nonce: fields.client_nonce, purpose: 'TRANSFER_SIGNING', consumed: false },
              { $set: { consumed: true } }
            );
          }

          const transfer = await Transfer.create({
            file_name: file_name,
            stored_name: pythonData.stored_name,
            file_group_id: crypto.randomBytes(16).toString('hex'),
            original_hash: pythonData.original_hash,
            encrypted_path: pythonData.encrypted_path,
            encrypted_key: pythonData.encrypted_key,
            nonce: pythonData.nonce,
            ecdh_public_key: pythonData.ecdh_public_key,
            ecdh_wrapped_key: pythonData.ecdh_wrapped_key,
            file_size: assembledFileSize,
            sender_id: req.user._id,
            receiver_id: receiver._id,
            status: 'encrypted',
            integrity_status: 'pending_download',
            anomaly_score: pythonData.anomaly_score,
            is_anomaly: pythonData.is_anomaly,
            anomaly_level: pythonData.anomaly_level,
            anomaly_reason: pythonData.anomaly_reason,
            cipher_algorithm: pythonData.cipher_algorithm,
            signature_verified: pythonData.signature_verified || false,
            signing_key_fingerprint: pythonData.key_fingerprint || ''
          });

          safeUnlink(assembledFilePath);

          const block = await appendToBlockchain('FILE_TRANSFER', {
            transfer_id: transfer._id,
            sender: req.user.email,
            receiver: receiver.email,
            file_size: transfer.file_size,
            classification: 'standard',
            ai_score: pythonData.anomaly_score,
            network_score: pythonData.network_risk_score,
            combined_score: pythonData.combined_risk_score,
            signature_verification: 'VERIFIED',
            signing_key_fingerprint: pythonData.key_fingerprint || ''
          });

          UPLOAD_STATUSES[upload_id] = { 
            status: 'completed', 
            result: {
              message: 'File uploaded successfully',
              classification_type: pythonData.classification_type || 'standard',
              encryption_mechanism_used: pythonData.cipher_algorithm || 'PFCE Streaming',
              transfer: transfer,
              blockchain: { id: block._id }
            }
          };

        } catch (bgErr) {
          safeUnlink(assembledFilePath);
          console.error('Background Processing Error:', bgErr.message);
          UPLOAD_STATUSES[upload_id] = { status: 'error', message: bgErr.message || 'Processing failed' };
        }
      });
    } catch (err) {
      if (tempFilePath) safeUnlink(tempFilePath);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  req.pipe(busboy);
};'''

send_file_match = re.search(r'exports\.sendFile = async \(req, res\) => \{.*?\n\};', code, re.DOTALL)
if send_file_match:
    code = code.replace(send_file_match.group(0), new_send_file)

upload_chunk_match = re.search(r'exports\.uploadChunk = async \(req, res\) => \{.*?\n\};', code, re.DOTALL)
if upload_chunk_match:
    code = code.replace(upload_chunk_match.group(0), new_upload_chunk)

with open('backend-node/src/controllers/fileController.js', 'w', encoding='utf-8') as f:
    f.write(code)
