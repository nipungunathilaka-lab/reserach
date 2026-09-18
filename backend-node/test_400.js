const axios = require('axios');
async function test() {
  try {
    const login = await axios.post('http://localhost:5001/api/auth/login', { email: 'admin@lab.local', password: 'adminpassword123!' });
    const token = login.data.access_token;

    const res = await axios.get('http://localhost:5001/api/crypto/key-status', { headers: { Authorization: `Bearer ${token}` } });
    console.log('Status code:', res.status, res.data);
  } catch (err) {
    console.error('Error status:', err.response ? err.response.status : err.message);
    if (err.response) console.error('Error data:', err.response.data);
  }
}
test();
