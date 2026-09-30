const mongoose = require('mongoose');

mongoose.set('toJSON', { virtuals: true });
mongoose.set('toObject', { virtuals: true });

// Listen to connection events for auto-reconnect transparency
mongoose.connection.on('disconnected', () => {
  console.warn('⚠️ MongoDB disconnected! Mongoose will automatically attempt to reconnect...');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected successfully!');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB runtime error:', err.message);
});

const connectDB = async (retries = 5) => {
  let currentUri = process.env.MONGO_URI;
  while (retries > 0) {
    try {
      const conn = await mongoose.connect(currentUri, {
        serverSelectionTimeoutMS: 5000, // Shortened to fail faster for fallback
        socketTimeoutMS: 60000,          // Wait 60 seconds for queries
        connectTimeoutMS: 5000,         // Wait 5 seconds for initial connection
        heartbeatFrequencyMS: 2000,      // Check server health every 2 seconds
      });
      console.log(`✅ MongoDB Connected on Startup: ${conn.connection.host}`);
      return; // Success!
    } catch (error) {
      console.error(`MongoDB Initial Connection Error: ${error.message}`);
      
      // Attempt fallback to localhost if it's a docker hostname
      if (currentUri.includes('mongodb://mongo:') || currentUri.includes('mongodb://mongodb:')) {
          console.warn('⚠️ Falling back to localhost for MongoDB...');
          currentUri = currentUri.replace('mongodb://mongo:', 'mongodb://localhost:').replace('mongodb://mongodb:', 'mongodb://localhost:');
      }
      
      retries -= 1;
      if (retries === 0) {
        console.error('❌ Failed to connect to MongoDB after multiple attempts. Please check your ISP or Atlas IP Whitelist.');
        throw error; // Throw so server.js knows it failed
      }
      console.log(`⏳ Retrying connection... (${retries} attempts left)`);
      await new Promise(res => setTimeout(res, 3000)); // Wait 3 seconds before retrying
    }
  }
};

module.exports = connectDB;
