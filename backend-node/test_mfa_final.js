const axios = require('axios');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: '../.env' });
dotenv.config({ path: '.env' }); // Load backend-node specific env

const API_URL = 'http://localhost:5000/api';

async function runTests() {
  console.log('=== MFA FULL END-TO-END VERIFICATION ===\n');

  try {
    const email = `test_final_${Date.now()}@example.com`;
    const password = 'Password123!';
    
    console.log('[PHASE 1] Register User & Verify successful MFA Login');
    const regRes = await axios.post(`${API_URL}/auth/register`, {
      full_name: 'Test Final', email, password, role: 'user'
    }).catch(e => e.response);
    
    const loginRes = await axios.post(`${API_URL}/auth/login`, { email, password }).catch(e => e.response);
    
    if (loginRes.data.success && loginRes.data.mfaRequired && !loginRes.data.access_token) {
      console.log('  -> Password accepted. MFA Challenge created. NO JWT issued.');
    } else {
      console.log('  -> FAILED: Password returned JWT or failed unexpectedly.', loginRes.data);
    }
    
    const challengeId = loginRes.data.challenge_id;
    const otp = loginRes.data.dev_otp;
    console.log(`  -> Obtained DEV OTP: ${otp}`);
    
    console.log('\n[PHASE 8] Protected API Before MFA');
    const protectedResBefore = await axios.get(`${API_URL}/auth/me`).catch(e => e.response);
    if (protectedResBefore.status === 401) {
      console.log('  -> Passed: Access denied (401) to protected API before MFA.');
    } else {
      console.log('  -> Failed: Access allowed to protected API before MFA!');
    }
    
    console.log('\n[PHASE 1] POST MFA verification with correct OTP');
    const verifyRes = await axios.post(`${API_URL}/auth/verify-mfa`, { challenge_id: challengeId, otp }).catch(e => e.response);
    let token = '';
    if (verifyRes.data.success && verifyRes.data.access_token) {
      token = verifyRes.data.access_token;
      console.log('  -> Passed: Correct OTP accepted. Real access JWT returned.');
    } else {
      console.log('  -> Failed: Could not verify OTP.', verifyRes.data);
    }

    console.log('\n[PHASE 9] Protected API After MFA');
    const protectedResAfter = await axios.get(`${API_URL}/auth/me`, { headers: { Authorization: `Bearer ${token}` } }).catch(e => e.response);
    if (protectedResAfter.status === 200 && protectedResAfter.data.success) {
      console.log('  -> Passed: Protected API access granted with MFA JWT.');
    } else {
      console.log('  -> Failed: Protected API denied.', protectedResAfter.data);
    }
    
    console.log('\n[PHASE 2] Verify Successful OTP is Single Use (Replay Test)');
    const replayRes = await axios.post(`${API_URL}/auth/verify-mfa`, { challenge_id: challengeId, otp }).catch(e => e.response);
    if (replayRes.status === 400 && replayRes.data.error.includes('consumed')) {
      console.log(`  -> Passed: Replay failed with status ${replayRes.status}. Error: ${replayRes.data.error}`);
    } else {
      console.log('  -> Failed: Replay succeeded!', replayRes.data);
    }

    console.log('\n[PHASE 3] Verify Resend Invalidates Old OTP');
    const login2Res = await axios.post(`${API_URL}/auth/login`, { email, password }).catch(e => e.response);
    const challengeId2 = login2Res.data.challenge_id;
    const otpA = login2Res.data.dev_otp;
    
    // Bypass cooldown directly in DB so we don't have to wait 60s
    await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/ai-secure-ft');
    const MfaChallenge = require('./src/models/MfaChallenge');
    await MfaChallenge.findByIdAndUpdate(challengeId2, { last_sent_at: new Date(Date.now() - 100000) });

    const resendRes = await axios.post(`${API_URL}/auth/resend-mfa`, { challenge_id: challengeId2 }).catch(e => e.response);
    const otpB = resendRes.data.dev_otp;
    const challengeId3 = resendRes.data.challenge_id; // new challenge

    const tryOtpARes = await axios.post(`${API_URL}/auth/verify-mfa`, { challenge_id: challengeId2, otp: otpA }).catch(e => e.response);
    if (tryOtpARes.status === 400 && tryOtpARes.data.error.includes('consumed')) {
      console.log('  -> Passed: OTP-A (old) rejected.');
    } else {
      console.log('  -> Failed: OTP-A accepted!', tryOtpARes.data);
    }

    const tryOtpBRes = await axios.post(`${API_URL}/auth/verify-mfa`, { challenge_id: challengeId3, otp: otpB }).catch(e => e.response);
    if (tryOtpBRes.status === 200 && tryOtpBRes.data.access_token) {
      console.log('  -> Passed: OTP-B (new) accepted.');
    } else {
      console.log('  -> Failed: OTP-B rejected!', tryOtpBRes.data);
    }

    console.log('\n[PHASE 4] Verify OTP Expiration');
    const login3Res = await axios.post(`${API_URL}/auth/login`, { email, password }).catch(e => e.response);
    const challengeId4 = login3Res.data.challenge_id;
    const otpExp = login3Res.data.dev_otp;
    
    await MfaChallenge.findByIdAndUpdate(challengeId4, { expires_at: new Date(Date.now() - 1000) });
    const expTryRes = await axios.post(`${API_URL}/auth/verify-mfa`, { challenge_id: challengeId4, otp: otpExp }).catch(e => e.response);
    if (expTryRes.status === 400 && expTryRes.data.error.includes('expired')) {
      console.log('  -> Passed: Expired OTP rejected. NO JWT.');
    } else {
      console.log('  -> Failed: Expired OTP accepted.', expTryRes.data);
    }

  } catch (error) {
    console.error('Test execution failed:', error.message);
  } finally {
    process.exit(0);
  }
}

runTests();
