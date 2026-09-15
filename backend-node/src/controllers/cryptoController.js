const crypto = require('crypto');
const SigningKey = require('../models/SigningKey');
const SigningChallenge = require('../models/SigningChallenge');
const BlockchainLog = require('../models/BlockchainLog');

// Generate cryptographically random nonce
function generateNonce() {
  return crypto.randomBytes(32).toString('base64url');
}

// Convert Base64 string to Buffer
function base64ToBuffer(base64) {
  return Buffer.from(base64, 'base64');
}

// Helper to append events to the blockchain ledger
const appendToBlockchain = async (eventType, detailsObj) => {
  const lastBlock = await BlockchainLog.findOne().sort({ timestamp: -1 });
  const previousHash = lastBlock ? lastBlock.block_hash : '0'.repeat(64);
  const detailsStr = JSON.stringify(detailsObj);
  const timestamp = Date.now();
  const dataToHash = `${timestamp}${eventType}${detailsStr}${previousHash}`;
  const blockHash = crypto.createHash('sha256').update(dataToHash).digest('hex');

  const block = await BlockchainLog.create({
    timestamp,
    event_type: eventType,
    details: detailsStr,
    previous_hash: previousHash,
    block_hash: blockHash
  });
  return block;
};

exports.registerKeyChallenge = async (req, res) => {
  try {
    const nonce = generateNonce();
    const expires_at = new Date(Date.now() + 5 * 60 * 1000); // 5 mins

    await SigningChallenge.create({
      user_id: req.user._id,
      nonce,
      purpose: 'REGISTRATION',
      expires_at
    });

    res.status(200).json({ success: true, nonce });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.registerKey = async (req, res) => {
  try {
    const { nonce, public_key_spki, public_key_fingerprint, signature } = req.body;

    // Verify challenge
    const challenge = await SigningChallenge.findOne({
      user_id: req.user._id,
      nonce,
      purpose: 'REGISTRATION',
      consumed: false,
      expires_at: { $gt: new Date() }
    });

    if (!challenge) {
      return res.status(400).json({ success: false, error: 'Invalid or expired registration challenge' });
    }

    // Verify signature using crypto.verify
    const spkiDer = base64ToBuffer(public_key_spki);
    const publicKeyObject = crypto.createPublicKey({
      key: spkiDer,
      format: 'der',
      type: 'spki'
    });

    const signatureBuffer = base64ToBuffer(signature);
    
    // RSA-PSS with SHA-256 and salt length 32
    const isVerified = crypto.verify(
      'sha256',
      Buffer.from(nonce, 'utf-8'),
      {
        key: publicKeyObject,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32
      },
      signatureBuffer
    );

    if (!isVerified) {
      return res.status(401).json({ success: false, error: 'Proof of possession signature verification failed' });
    }

    // Mark challenge consumed
    challenge.consumed = true;
    await challenge.save();

    // Archive existing keys
    await SigningKey.updateMany(
      { user_id: req.user._id, status: 'ACTIVE' },
      { $set: { status: 'SUPERSEDED' } }
    );

    const keyCount = await SigningKey.countDocuments({ user_id: req.user._id });

    // Save new key
    const newKey = await SigningKey.create({
      user_id: req.user._id,
      public_key_spki,
      public_key_fingerprint,
      key_version: keyCount + 1,
      proof_of_possession_verified: true
    });

    await appendToBlockchain('SIGNING_KEY_REGISTERED', {
      user_id: req.user._id,
      key_fingerprint: public_key_fingerprint,
      key_version: newKey.key_version
    });

    res.status(200).json({ success: true, message: 'Signing key registered successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.transferChallenge = async (req, res) => {
  try {
    const nonce = generateNonce();
    const expires_at = new Date(Date.now() + 15 * 60 * 1000); // 15 mins for large uploads

    await SigningChallenge.create({
      user_id: req.user._id,
      nonce,
      purpose: 'TRANSFER_SIGNING',
      expires_at
    });

    res.status(200).json({ success: true, nonce });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.checkKeyStatus = async (req, res) => {
  try {
    const activeKey = await SigningKey.findOne({ user_id: req.user._id, status: 'ACTIVE' });
    res.status(200).json({ success: true, has_active_key: !!activeKey, fingerprint: activeKey ? activeKey.public_key_fingerprint : null });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
