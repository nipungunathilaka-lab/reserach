const express = require('express');
const fs = require('fs');

// Ensure uploads directory exists for file streaming
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads', { recursive: true });
}
const cors = require('cors');
const dotenv = require('dotenv');
const connectDB = require('./src/config/db');

// Load env vars
dotenv.config();

const app = express();

// Body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Enable CORS
app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true
}));

// Mount routers
app.use('/api/auth', require('./src/routes/auth'));
app.use('/api/users', require('./src/routes/users'));
app.use('/api/files', require('./src/routes/files'));
app.use('/api/audit', require('./src/routes/audit'));
app.use('/api/dashboard', require('./src/routes/dashboard'));
app.use('/api/crypto', require('./src/routes/crypto'));

// Basic error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.statusCode || 500).json({
    success: false,
    error: err.message || 'Server Error'
  });
});

// Connect to database and then start the server
connectDB().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, console.log(`Server running on port ${PORT}`));
}).catch(err => {
  console.error("Failed to connect to database on startup:", err);
});
