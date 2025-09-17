require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
const PORT = process.env.PORT || 5500;

// Middleware
// Replace '*' with your frontend URL in production, e.g. 'http://localhost:5500' or your deployed frontend URL
app.use(cors({ origin: '*' }));
app.use(express.json());

// In-memory user store (for demo; replace with DB in production)
const users = [];

// Helper: Generate JWT token
function generateToken(user) {
  return jwt.sign(
    { email: user.email, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// Middleware: Authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token missing' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Routes

// Test route
app.get('/', (req, res) => {
  res.send('Weather Oracle Backend is running');
});

// Sign Up
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ message: 'All fields are required' });

  const existingUser  = users.find(u => u.email === email);
  if (existingUser )
    return res.status(409).json({ message: 'User  already exists' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser  = { name, email, password: hashedPassword };
    users.push(newUser );

    const token = generateToken(newUser );
    res.status(201).json({ token });
  } catch (err) {
    console.error('Sign up error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Sign In
app.post('/api/signin', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'Email and password required' });

  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  try {
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const token = generateToken(user);
    res.json({ token });
  } catch (err) {
    console.error('Sign in error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Weather API Proxy (Protected Route)
app.get('/api/weather', authenticateToken, async (req, res) => {
  const location = req.query.location;
  if (!location) return res.status(400).json({ message: 'Location is required' });

  try {
    const apiKey = process.env.OPENWEATHER_API_KEY;
    if (!apiKey) {
      console.error('OpenWeather API key missing');
      return res.status(500).json({ message: 'Server configuration error' });
    }

    const weatherRes = await fetch(
      `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(location)}&units=metric&appid=${apiKey}`
    );

    if (!weatherRes.ok) {
      const errorData = await weatherRes.json().catch(() => ({}));
      console.error('OpenWeather API error:', errorData);
      return res.status(weatherRes.status).json({ message: errorData.message || 'Failed to fetch weather data' });
    }

    const weatherData = await weatherRes.json();

    res.json({
      location: `${weatherData.name}, ${weatherData.sys.country}`,
      temperature: weatherData.main.temp,
      description: weatherData.weather[0].description,
      icon: weatherData.weather[0].icon,
      humidity: weatherData.main.humidity,
      windSpeed: weatherData.wind.speed
    });
  } catch (error) {
    console.error('Weather fetch error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});