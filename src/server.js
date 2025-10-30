require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const axios = require('axios');
const cors = require('cors');
const express = require('express');
const path = require('path');

const app = express();

app.use(express.static(path.join(__dirname, "../frontend/build")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/build", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

const BASE_PRICE_USD = parseFloat(process.env.PREMIUM_PRICE); // 9.99
const EXCHANGE_API_KEY = process.env.EXCHANGE_API_KEY;


const allowedOrigins = [
  'http://localhost:5500', // VS Code Live Server
  'http://127.0.0.1:5500',
  'http://localhost:3000', // Frontend on localhost
  'http://127.0.0.1:3000',
];

// Configure CORS
app.use(
  cors({
    origin: (origin, callback) => {
      console.log(`📡 Request from origin: ${origin || 'null (local file or Postman)'}`);

      // Allow requests with no origin (local file, Postman, curl)
      if (!origin || origin === 'null') {
        console.log('🌐 Allowing request with null origin (local file, Postman, or same-origin script)');
        return callback(null, true);
      }

      // Allow if origin is in whitelist
      if (allowedOrigins.includes(origin)) {
        console.log('✅ CORS allowed origin:', origin);
        return callback(null, true);
      }

      // Otherwise block
      console.log('❌ CORS blocked origin:', origin);
      return callback(new Error('Not allowed by CORS policy'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// Handle preflight (OPTIONS) explicitly
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200);
});

// Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// MongoDB Connection (Log status only after connect)
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected successfully');
    // Log full status ONLY after connection
    console.log('📊 Services Status:');
    console.log(`   - MongoDB: ✅ Connected`);
    console.log(`   - OpenWeather API: ${!!process.env.OPENWEATHER_API_KEY ? '✅ Ready' : '❌ Missing Key'}`);
    console.log(`   - Stripe: ${!!process.env.STRIPE_SECRET_KEY ? '✅ Configured' : '❌ Missing Key'}`);
    console.log(`   - Exchange API: ${!!process.env.EXCHANGE_API_KEY ? '✅ Ready' : '❌ Missing Key'}`);
    console.log('🔧 Test Endpoints:');
    console.log(`   - Health: GET /api/health`);
    console.log(`   - Signup: POST /api/signup`);
    console.log(`   - Premium: POST /api/premium/upgrade { "currency": "USD" } (auth required)`);
  })
  .catch(err => console.error('MongoDB connection error:', err));

// Models
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
  imageUrl: { type: String, default: '' },
  isPremium: { type: Boolean, default: false }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User ', userSchema);

const historySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User ', required: true },
  location: { type: String, required: true, trim: true },
  date: { type: Date, default: Date.now }
}, { timestamps: true });

historySchema.index({ userId: 1, date: -1 });
const History = mongoose.model('History', historySchema);

// Multer Middleware
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, process.env.UPLOADS_PATH || './uploads'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) cb(null, true);
  else cb(new Error('Only image files are allowed'), false);
};

const upload = multer({
  storage,
  limits: { fileSize: parseInt(process.env.MAX_FILE_SIZE) || 5242880 },  // 5MB
  fileFilter
});

// Auth Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token provided' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(401).json({ message: 'Invalid token' });

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Health Check
app.get('/api/health', (req, res) => {
  console.log('Health check requested');
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    stripe: !!process.env.STRIPE_SECRET_KEY ? 'Configured' : 'Missing',
    openweather: !!process.env.OPENWEATHER_API_KEY ? 'Ready' : 'Missing'
  });
});

// Auth Routes
app.post('/api/signup', upload.single('profileImage'), async (req, res) => {
  console.log('Signup request received');
  try {
    let { name, email, password } = req.body;
    email = email?.toLowerCase().trim();

    if (!name || !email || !password) {
      console.log('Signup validation failed: Missing fields');
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (password.length < 6) {
      console.log('Signup validation failed: Password too short');
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    console.log(`Checking existing user for email: ${email}`);
    const existingUser  = await User.findOne({ email });
    console.log('Existing user check complete:', !!existingUser );
    if (existingUser ) {
      return res.status(400).json({ message: 'Account already exists' });
    }

    const userData = { name, email, password };
    if (req.file) userData.imageUrl = `/uploads/${req.file.filename}`;

    console.log('Creating new user...');
    const user = new User(userData);
    await user.save();
    console.log(`User  created: ${user._id}`);

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    console.log('Signup successful - sending response');
    res.status(201).json({
      token,
      user: {
        name: user.name,
        email: user.email,
        imageUrl: user.imageUrl,
        isPremium: user.isPremium
      }
    });
  } catch (error) {
    console.error('Signup error details:', error.message, error.stack);  // Full trace
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/api/signin', async (req, res) => {
  console.log('Signin request received');
  try {
    const { email, password } = req.body;
    const normalizedEmail = email?.toLowerCase().trim();

    if (!normalizedEmail || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        name: user.name,
        email: user.email,
        imageUrl: user.imageUrl,
        isPremium: user.isPremium
      }
    });
  } catch (error) {
    console.error('Signin error details:', error.message, error.stack);
    res.status(500).json({ message: 'Server error during signin' });
  }
});

// Profile Routes
app.get('/api/profile', auth, async (req, res) => {
  console.log('Profile get request for user:', req.user._id);
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (error) {
    console.error('Profile get error details:', error.message);
    res.status(500).json({ message: 'Server error fetching profile' });
  }
});

app.put('/api/profile', auth, upload.single('profileImage'), async (req, res) => {
  console.log('Profile update request for user:', req.user._id);
  try {
    const updates = { name: req.body.name?.trim() };
    const normalizedEmail = req.body.email?.toLowerCase().trim();
    if (normalizedEmail && normalizedEmail !== req.user.email) {
      const existing = await User.findOne({ email: normalizedEmail });
      if (existing) return res.status(400).json({ message: 'Email already in use' });
      updates.email = normalizedEmail;
    }

    if (req.file) updates.imageUrl = `/uploads/${req.file.filename}`;

    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true, runValidators: true }).select('-password');
    res.json(user);
  } catch (error) {
    console.error('Profile update error details:', error.message);
    res.status(500).json({ message: 'Server error updating profile' });
  }
});

app.post('/api/change-password', auth, async (req, res) => {
  console.log('Password change request for user:', req.user._id);
  try {
    const { current, newPassword } = req.body;

    if (!current || !newPassword || newPassword.length < 6) {
      return res.status(400).json({ message: 'Invalid input for password change' });
    }

    const user = await User.findById(req.user._id);
    const isMatch = await user.comparePassword(current);
    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    user.password = newPassword;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Password change error details:', error.message);
    res.status(500).json({ message: 'Server error changing password' });
  }
});

// Weather Route
app.get('/api/weather', auth, async (req, res) => {
  console.log('Weather request for location:', req.query.location, 'by user:', req.user._id);
  try {
    const { location } = req.query;
    if (!location) {
      return res.status(400).json({ message: 'Location is required' });
    }

    const API_KEY = process.env.OPENWEATHER_API_KEY;
    const BASE_URL = 'https://api.openweathermap.org/data/2.5';

    const currentRes = await axios.get(`${BASE_URL}/weather`, {
      params: { q: location, appid: API_KEY, units: 'metric' }
    });

    const weatherData = currentRes.data;

    let forecastData = null;
    if (req.user.isPremium) {
      const forecastRes = await axios.get(`${BASE_URL}/forecast`, {
        params: { q: location, appid: API_KEY, units: 'metric' }
      });
      forecastData = forecastRes.data;
    }

    await History.create({ userId: req.user._id, location });

    const historyCount = await History.countDocuments({ userId: req.user._id });
    if (historyCount > 50) {
      const oldestRecords = await History.find({ userId: req.user._id }).sort({ date: 1 }).limit(historyCount - 50);
      for (const record of oldestRecords) {
        await History.findByIdAndDelete(record._id);
      }
    }

    res.json({ ...weatherData, forecast: forecastData });
  } catch (error) {
    console.error('Weather API error details:', error.response?.data || error.message);
    if (error.response?.status === 404) {
      return res.status(404).json({ message: 'Location not found' });
    }
    res.status(500).json({ message: 'Error fetching weather data' });
  }
});

// History Routes
app.get('/api/history', auth, async (req, res) => {
  console.log('History get request for user:', req.user._id);
  try {
    const history = await History.find({ userId: req.user._id }).sort({ date: -1 }).select('location date');
    res.json(history);
  } catch (error) {
    console.error('History get error details:', error.message);
    res.status(500).json({ message: 'Server error fetching history' });
  }
});

app.post('/api/history', auth, async (req, res) => {
  console.log('History add request for user:', req.user._id);
  try {
    const { location } = req.body;
    if (!location) return res.status(400).json({ message: 'Location is required' });

    await History.create({ userId: req.user._id, location });

    const historyCount = await History.countDocuments({ userId: req.user._id });
    if (historyCount > 50) {
      const oldestRecords = await History.find({ userId: req.user._id }).sort({ date: 1 }).limit(historyCount - 50);
      for (const record of oldestRecords) {
        await History.findByIdAndDelete(record._id);
      }
    }

    res.json({ message: 'History added' });
  } catch (error) {
    console.error('History add error details:', error.message);
    res.status(500).json({ message: 'Server error adding history' });
  }
});

app.delete('/api/history', auth, async (req, res) => {
  console.log('History clear request for user:', req.user._id);
  try {
    await History.deleteMany({ userId: req.user._id });
    res.json({ message: 'History cleared' });
  } catch (error) {
    console.error('History clear error details:', error.message);
    res.status(500).json({ message: 'Server error clearing history' });
  }
});

// -------------------- PREMIUM UPGRADE AND CHECKOUT --------------------

// Premium Upgrade Route with Auto Currency Detection
app.post('/api/premium/upgrade', auth, async (req, res) => {
  console.log('Premium upgrade request for user:', req.user._id);

  try {
    if (req.user.isPremium) {
      return res.status(400).json({ message: 'Already premium' });
    }

    const BASE_PRICE_USD = parseFloat(process.env.PREMIUM_PRICE || 9.99);
    let currency = 'USD';

    // 10 countries mapping: countryCode -> currency
    const countryCurrencyMap = {
      US: 'USD', GB: 'GBP', EU: 'EUR', NG: 'NGN', IN: 'INR',
      JP: 'JPY', CA: 'CAD', AU: 'AUD', ZA: 'ZAR', BR: 'BRL'
    };

    // Detect IP from headers or fallback
    let ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.connection.remoteAddress;
    if (ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');

    try {
      const geoRes = await axios.get(`http://ip-api.com/json/${ip}`);
      const countryCode = geoRes.data.countryCode;
      if (countryCurrencyMap[countryCode]) {
        currency = countryCurrencyMap[countryCode];
      }
      console.log(`Detected country: ${geoRes.data.country}, currency: ${currency}, IP: ${ip}`);
    } catch (geoError) {
      console.error('GeoIP API error, using USD fallback:', geoError.message);
    }

    // Convert USD to local currency
    let unitAmountCents = Math.round(BASE_PRICE_USD * 100);
    try {
      const exchangeRes = await axios.get(`https://v6.exchangerate-api.com/v6/${EXCHANGE_API_KEY}/latest/USD`);
      const rates = exchangeRes.data.conversion_rates;
      const rate = rates[currency] || 1;
      unitAmountCents = Math.round(BASE_PRICE_USD * rate * 100);
      console.log(`Exchange rate for ${currency}: ${rate}, Unit amount: ${unitAmountCents} cents`);
    } catch (exchangeError) {
      console.error('Exchange API error, using fallback rates:', exchangeError.message);
      const fallbackRates = { USD: 1, EUR: 0.92, GBP: 0.79, NGN: 1600, INR: 83, JPY: 150, CAD: 1.35, AUD: 1.5, ZAR: 19, BRL: 5 };
      const rate = fallbackRates[currency] || 1;
      unitAmountCents = Math.round(BASE_PRICE_USD * rate * 100);
      console.log(`Fallback rate for ${currency}: ${rate}, Unit amount: ${unitAmountCents} cents`);
    }

    // Create Stripe checkout session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: currency.toLowerCase(),
          product_data: {
            name: 'Weather Oracle Premium',
            description: 'Monthly subscription with advanced features (3-day forecasts, ad-free, priority support)'
          },
          unit_amount: unitAmountCents,
          recurring: { interval: 'month' }
        },
        quantity: 1
      }],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}?success=true&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}?canceled=true`,
      customer_email: req.user.email,
      metadata: { userId: req.user._id.toString(), email: req.user.email }
    });

    console.log('Stripe session created successfully');
    res.json({ session: { url: session.url } });

  } catch (error) {
    console.error('Premium upgrade error details:', error.message, error.stack);
    res.status(500).json({ message: 'Error creating payment session' });
  }
});

// Stripe Webhook (Activates premium on successful payment)
app.post('/api/premium/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  console.log('Webhook received');
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    if (!process.env.STRIPE_WEBHOOK_SECRET) {
      return res.status(400).json({ message: 'Webhook secret not configured' });
    }
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    console.log(`Webhook verified: ${event.type}`);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).json({ message: 'Webhook signature verification failed' });
  }

  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object;
      const userId = session.metadata.userId;
      if (userId && session.payment_status === 'paid') {
        const user = await User.findById(userId);
        if (user && !user.isPremium) {
          await User.findByIdAndUpdate(userId, { isPremium: true });
          console.log(`Premium activated via webhook for user ${userId}`);
        }
      }
      break;
    default:
      console.log(`Unhandled webhook event: ${event.type}`);
  }

  res.json({ received: true });
});

// Global Error Handler (For Multer and general errors)
app.use((error, req, res, next) => {
  console.error('Global error handler:', error.message, error.stack);
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large. Max size: 5MB' });
    }
  }
  if (error.message === 'Only image files are allowed') {
    return res.status(400).json({ message: error.message });
  }
  res.status(500).json({ message: 'Internal server error' });
});

// 404 Handler (For unmatched routes)
app.use('*', (req, res) => {
  console.log(`404: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ message: 'Route not found' });
});

// Server Startup (Status logs inside MongoDB connect .then() )
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log('Starting Weather Oracle Backend...');
});

// Graceful Shutdown
process.on('SIGTERM', shutDown);
process.on('SIGINT', shutDown);

async function shutDown() {
  console.log('\n🛑 Shutting down gracefully...');
  await mongoose.connection.close();
  console.log('MongoDB connection closed');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
}

if (require.main === module) {
  // Ensure server starts only if run directly
}