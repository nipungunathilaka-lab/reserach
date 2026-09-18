const jwt = require('jsonwebtoken');
const axios = require('axios');
const token = jwt.sign({ id: '64f0a0d5b94f114c0a5a22bb' }, process.env.JWT_SECRET || 'default-jwt-secret');
axios.get('http://localhost:5001/api/crypto/key-status', { headers: { Authorization: `Bearer ${token}` } })
  .then(res => console.log('STATUS:', res.status, 'BODY:', res.data))
  .catch(err => console.log('ERR STATUS:', err.response?.status, 'ERR BODY:', err.response?.data));
