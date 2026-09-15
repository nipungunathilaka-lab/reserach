const mongoose = require('mongoose');
const axios = require('axios');
const crypto = require('crypto');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '.env') });

const BlockchainLog = require('./src/models/BlockchainLog');

async function verifyChain() {
    console.log('==========================================');
    console.log('TC-06 AUDIT CHAIN VERIFICATION');
    console.log('==========================================');

    try {
        const pythonUrl = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
        const res = await axios.get(`${pythonUrl}/internal/audit/verify-ledger`);
        const verification = res.data;

        console.log(`\nVerified Records: ${verification.checked_records}`);
        console.log(`Verification Status: ${verification.status}`);
        if (!verification.valid) {
            console.log(`\n*** TAMPERING / INTEGRITY FAILURE DETECTED ***`);
            console.log(`Reason: ${verification.reason}`);
            console.log(`Invalid Record ID: ${verification.invalid_record_id}`);
            console.log(`Invalid Sequence: ${verification.invalid_sequence}`);
        }

        console.log('\n==========================================');
        console.log(`CHAIN STATUS: ${verification.valid ? 'VALID' : 'INVALID'}`);
        console.log('==========================================');
        
    } catch (err) {
        console.error('Error contacting authoritative verifier:', err.message);
        console.log('\n==========================================');
        console.log('CHAIN STATUS: VERIFICATION_ERROR');
        console.log('==========================================');
        process.exit(1);
    }
}

verifyChain().catch(err => {
    console.error(err);
    process.exit(1);
});