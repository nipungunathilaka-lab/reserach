const axios = require('axios');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: '../.env' });

const API_URL = 'http://localhost:5001/api/auth';

async function runTests() {
  console.log('=== MFA Backend Tests ===\n');

  try {
    // We assume the DB is running locally and we can grab a user from DB.
    await mongoose.connect(process.env.DATABASE_URL.replace('sqlite:///./', 'sqlite://localhost/').replace('sqlite', 'mongodb') || 'mongodb://localhost:27017/ai-secure-ft', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    }).catch(e => console.log('Could not connect to DB for test setup. We will just use API.'));
    
    // Create a unique test user
    const email = `testuser_${Date.now()}@example.com`;
    const password = 'password123';
    
    console.log('[Test 1] Register User (should return challenge_id)');
    const regRes = await axios.post(`${API_URL}/register`, {
      full_name: 'Test User',
      email,
      password,
      role: 'user'
    }).catch(e => e.response);
    
    if (regRes.data.success && regRes.data.mfaRequired) {
      console.log('✅ Passed. Challenge ID:', regRes.data.challenge_id);
    } else {
      console.log('❌ Failed.', regRes.data);
    }
    
    console.log('\n[Test 2] Invalid Password (should not return challenge)');
    const loginFail = await axios.post(`${API_URL}/login`, { email, password: 'wrongpassword' }).catch(e => e.response);
    if (loginFail.status === 401 && !loginFail.data.challenge_id) {
      console.log('✅ Passed.');
    } else {
      console.log('❌ Failed.', loginFail.data);
    }

    console.log('\n[Test 3] Password success requires MFA (no JWT)');
    const loginRes = await axios.post(`${API_URL}/login`, { email, password }).catch(e => e.response);
    if (loginRes.data.success && loginRes.data.mfaRequired && !loginRes.data.access_token) {
      console.log('✅ Passed. Challenge ID:', loginRes.data.challenge_id);
    } else {
      console.log('❌ Failed.', loginRes.data);
    }
    const challengeId = loginRes.data.challenge_id;

    console.log('\n[Test 4] Wrong OTP');
    const wrongOtpRes = await axios.post(`${API_URL}/verify-mfa`, { challenge_id: challengeId, otp: '000000' }).catch(e => e.response);
    if (wrongOtpRes.status === 401 && wrongOtpRes.data.error.includes('attempt(s) remaining')) {
      console.log('✅ Passed.', wrongOtpRes.data.error);
    } else {
      console.log('❌ Failed.', wrongOtpRes.data);
    }

    console.log('\n[Test 5] Maximum attempts');
    // Let's exhaust attempts (4 remaining)
    for (let i = 0; i < 4; i++) {
      await axios.post(`${API_URL}/verify-mfa`, { challenge_id: challengeId, otp: '000000' }).catch(e => e.response);
    }
    const maxAttemptRes = await axios.post(`${API_URL}/verify-mfa`, { challenge_id: challengeId, otp: '000000' }).catch(e => e.response);
    if (maxAttemptRes.status === 400 && maxAttemptRes.data.error.includes('consumed')) {
      console.log('✅ Passed. Challenge locked and consumed.');
    } else {
      console.log('❌ Failed.', maxAttemptRes.data);
    }

    console.log('\n[Test 6] Resend limits & cooldown');
    // Login again to get a fresh challenge
    const loginRes2 = await axios.post(`${API_URL}/login`, { email, password }).catch(e => e.response);
    const challengeId2 = loginRes2.data.challenge_id;

    const resendRes1 = await axios.post(`${API_URL}/resend-mfa`, { challenge_id: challengeId2 }).catch(e => e.response);
    if (resendRes1.status === 429 && resendRes1.data.error.includes('wait')) {
      console.log('✅ Passed Cooldown check.', resendRes1.data.error);
    } else {
      console.log('❌ Failed Cooldown check.', resendRes1.data);
    }

  } catch (error) {
    console.error('Test execution failed:', error.message);
  } finally {
    process.exit(0);
  }
}

runTests();
