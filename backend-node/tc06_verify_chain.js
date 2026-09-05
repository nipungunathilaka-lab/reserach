const mongoose = require('mongoose');
const crypto = require('crypto');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '.env') });

const BlockchainLog = require('./src/models/BlockchainLog');

async function verifyChain() {
    await mongoose.connect(process.env.MONGO_URI);

    const blocks = await BlockchainLog.find().sort({ timestamp: 1 });

    console.log('==========================================');
    console.log('TC-06 AUDIT CHAIN VERIFICATION');
    console.log('==========================================');

    let valid = true;
    let expectedPreviousHash = '0'.repeat(64);

    for (let i = 0; i < blocks.length; i++) {
        const block = blocks[i];

        const timestamp = new Date(block.timestamp).getTime();

        const dataToHash =
            `${timestamp}${block.event_type}${block.details}${block.previous_hash}`;

        const calculatedHash = crypto
            .createHash('sha256')
            .update(dataToHash)
            .digest('hex');

        const previousHashValid =
            block.previous_hash === expectedPreviousHash;

        const blockHashValid =
            block.block_hash === calculatedHash;

        console.log(`\nBlock ${i + 1}`);
        console.log(`Event Type          : ${block.event_type}`);
        console.log(`Previous Hash Match : ${previousHashValid}`);
        console.log(`Block Hash Match    : ${blockHashValid}`);

        if (!previousHashValid || !blockHashValid) {
            valid = false;

            console.log('*** TAMPERING / HASH MISMATCH DETECTED ***');
        }

        expectedPreviousHash = block.block_hash;
    }

    console.log('\n==========================================');
    console.log(`CHAIN STATUS: ${valid ? 'VALID' : 'INVALID'}`);
    console.log('==========================================');

    await mongoose.disconnect();
}

verifyChain().catch(err => {
    console.error(err);
    process.exit(1);
});