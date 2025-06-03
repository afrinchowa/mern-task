require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const User = require('./models/User');

const app = express();

// === Middlewares ===
app.use(cors({
  origin: 'http://localhost:5173', // React app origin
  credentials: true, // Allow sending cookies
}));
app.use(express.json());
app.use(cookieParser());

// === MongoDB Connection ===
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error(' MongoDB connection error:', err));

// === Constants ===
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// === Utility Functions ===
function isValidPassword(password) {
  return /^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})/.test(password);
}

async function areShopsUnique(shops) {
  const user = await User.findOne({ shops: { $in: shops } });
  return !user; // true if no user found = shops are unique
}

// === Root Route ===
app.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: ' Welcome to the MERN Shop Backend API!',
    docs: '/api/docs (coming soon)',
    version: '1.0.0'
  });
});

// === Auth Routes ===

// Signup Route
app.post('/signup', async (req, res) => {
  const { username, password, shops } = req.body;

  if (!username || !password || !shops || shops.length < 3) {
    return res.status(400).json({ message: 'Please provide username, password, and at least 3 shops.' });
  }

  if (!isValidPassword(password)) {
    return res.status(400).json({ message: 'Password must be 8+ chars with at least one number and special char.' });
  }

  if (!(await areShopsUnique(shops))) {
    return res.status(400).json({ message: 'One or more shop names are already taken.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, shops });
    await newUser.save();
    res.status(201).json({ message: 'User created successfully!' });
  } catch (err) {
    console.error('Signup error:', err);  // Add detailed logging
    if (err.code === 11000) {
      return res.status(400).json({ message: 'Username already exists.' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Signin Route
app.post('/signin', async (req, res) => {
  const { username, password, rememberMe } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

  const expiresIn = rememberMe ? '7d' : '30m';

  const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn });

  res.cookie('token', token, {
    httpOnly: true,
    maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 30 * 60 * 1000,
    sameSite: 'lax',
    domain: 'localhost',
    secure: false,
  });

  res.json({ message: 'Logged in successfully' });
});

// === Middleware ===
function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: 'Token is not valid' });
  }
}

// === Protected Routes ===

// Profile route
app.get('/profile', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });

  res.json({ username: user.username, shops: user.shops });
});

// Logout route
app.post('/logout', (req, res) => {
  res.clearCookie('token', { domain: 'localhost', path: '/' });
  res.json({ message: 'Logged out' });
});

// === Start Server ===
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(` Server running on http://localhost:${PORT}`));
