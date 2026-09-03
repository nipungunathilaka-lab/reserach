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
  while (retries > 0) {
    try {
      const conn = await mongoose.connect(process.env.MONGO_URI, {
        serverSelectionTimeoutMS: 60000, // Wait 60 seconds before failing on flaky networks
        socketTimeoutMS: 60000,          // Wait 60 seconds for queries
        connectTimeoutMS: 60000,         // Wait 60 seconds for initial connection
        heartbeatFrequencyMS: 2000,      // Check server health every 2 seconds
      });
      console.log(`✅ MongoDB Connected on Startup: ${conn.connection.host}`);
      return; // Success!
    } catch (error) {
      console.error(`MongoDB Initial Connection Error: ${error.message}`);
      retries -= 1;
      if (retries === 0) {
        console.error('❌ Failed to connect to MongoDB after multiple attempts. Please check your ISP or Atlas IP Whitelist.');
        throw error; // Throw so server.js knows it failed
      }
      console.log(`⏳ Retrying connection... (${retries} attempts left)`);
      await new Promise(res => setTimeout(res, 5000)); // Wait 5 seconds before retrying
    }
  }
};

module.exports = connectDB;
