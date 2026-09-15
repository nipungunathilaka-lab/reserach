const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');

async function test() {
    fs.writeFileSync('test_node.txt', 'Hello from node!');
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256').update('Hello from node!').digest('hex');
    const form = new FormData();
    // Simulate what fileController.js does
    form.append('file', fs.createReadStream('test_node.txt'), 'test_node.txt');
    form.append('transfer_id', 'upload-node');
    form.append('sender_id', 'sender-node');
    form.append('receiver_id', 'receiver-node');
    form.append('file_sha256', hash);
    form.append('issued_at', '2026-09-11T16:30:20.123Z');
    form.append('client_nonce', 'nonce-node');
    form.append('original_file_sha256', hash);
    form.append('client_signature', 'test'); // this will fail base64 decoding correctly

    try {
        const response = await axios.post('http://localhost:8000/internal/crypto/encrypt', form, {
            headers: form.getHeaders()
        });
        console.log(response.status);
    } catch (e) {
        console.log(e.response ? e.response.status : e.message);
    }
}
test();
