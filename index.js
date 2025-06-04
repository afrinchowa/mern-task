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
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// === MongoDB Connection Caching ===
let cached = global.mongoose;
if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectToDatabase() {
  if (cached.conn) return cached.conn;

  if (!cached.promise) {
    const opts = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    };
    cached.promise = mongoose.connect(process.env.MONGO_URI, opts).then((mongoose) => mongoose);
  }

  cached.conn = await cached.promise;
  return cached.conn;
}

// === Constants ===
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// === Utility Functions ===
function isValidPassword(password) {
  return /^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})/.test(password);
}

async function areShopsUnique(shops) {
  const user = await User.findOne({ shops: { $in: shops } });
  return !user;
}

// === API Router (/api prefix) ===
const router = express.Router();

// -- API health check --
router.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: 'Welcome to the MERN Shop Backend API!',
    version: '1.0.0',
  });
});

// -- Signup Route --
router.post('/signup', async (req, res) => {
  await connectToDatabase();
  const { username, password, shops } = req.body;

  if (!username || !password || !shops || shops.length < 3) {
    return res.status(400).json({ message: 'Provide username, password, and at least 3 shops.' });
  }

  if (!isValidPassword(password)) {
    return res.status(400).json({ message: 'Password must be 8+ characters with one number and special character.' });
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
    console.error('❌ Signup error:', err);
    if (err.code === 11000) {
      return res.status(400).json({ message: 'Username already exists.' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// -- Signin Route --
router.post('/signin', async (req, res) => {
  await connectToDatabase();
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
    secure: process.env.NODE_ENV === 'production',
  });

  res.json({ message: 'Logged in successfully' });
});

// -- Middleware to protect routes --
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

// -- Profile Route --
router.get('/profile', authenticateToken, async (req, res) => {
  await connectToDatabase();
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });

  res.json({ username: user.username, shops: user.shops });
});

// -- Logout Route --
router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    path: '/',
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  });
  res.json({ message: 'Logged out successfully' });
});

// === Register Routers ===
app.use('/api', router);

// === Root Path Response ===
app.get('/', (req, res) => {
  res.send(`
    <h1>MERN Shop Backend API</h1>
    <p>Server is running! Try accessing <code>/api</code> for API info.</p>
  `);
});

// === Start Server ===
const PORT = process.env.PORT || 4000;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
}

module.exports = app;
