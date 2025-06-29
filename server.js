const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);

// Add middleware for parsing JSON
app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname)));

// Root route handler
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Authentication routes
app.post('/auth/register', (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !password) {
    return res.json({ success: false, message: 'Username and password are required' });
  }

  if (username.length < 2) {
    return res.json({ success: false, message: 'Username must be at least 2 characters long' });
  }

  if (password.length < 6) {
    return res.json({ success: false, message: 'Password must be at least 6 characters long' });
  }

  // Check for invalid characters in username
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    return res.json({ success: false, message: 'Username can only contain letters, numbers, hyphens, and underscores' });
  }

  const result = createUser(username, email, password);
  res.json(result);
});

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ success: false, message: 'Username and password are required' });
  }

  const result = authenticateUser(username, password);
  res.json(result);
});

app.post('/auth/logout', (req, res) => {
  const { token } = req.body;
  if (token) {
    authSessions.delete(token);
  }
  res.json({ success: true });
});

app.get('/auth/verify', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const session = verifyToken(token);

  if (session) {
    res.json({ 
      success: true, 
      username: session.username, 
      isAdmin: session.isAdmin 
    });
  } else {
    res.json({ success: false, message: 'Invalid token' });
  }
});

// Socket.IO setup with improved configuration
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000,
  upgradeTimeout: 30000,
  allowEIO3: true
});

// Store active users and server rooms
const activeUsers = new Map();
const serverRooms = new Map();
const adminUsers = new Set();
const customServers = new Map(); // Store custom created servers
const userProfiles = new Map(); // Store user profiles
const messageThreads = new Map(); // Store message threads
const serverRoles = new Map(); // Store server roles
const userRoles = new Map(); // Store user roles per server
const pinnedMessages = new Map(); // Store pinned messages per server
const messageReactions = new Map(); // Store message reactions
const messageHistory = new Map(); // Store message history per server
const typingUsers = new Map(); // Store typing users per server

// Pastebin API configuration
const PASTEBIN_API_KEY = '8KDpz8RhxCoDj12iF6d8co4AKyfNIknt';
const PASTEBIN_BASE_URL = 'https://pastebin.com/api/api_post.php';

// Storage paste IDs for data persistence
let USERS_PASTE_ID = null;
let SESSIONS_PASTE_ID = null;

// User database for registration/login
const registeredUsers = new Map(); // Store registered users with passwords
const authSessions = new Map(); // Store auth sessions

// Pastebin API functions
async function createPaste(content, title) {
  const params = new URLSearchParams({
    api_dev_key: PASTEBIN_API_KEY,
    api_option: 'paste',
    api_paste_code: content,
    api_paste_name: title,
    api_paste_private: '1', // Private paste
    api_paste_expire_date: 'N' // Never expire
  });

  try {
    const response = await fetch(PASTEBIN_BASE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params
    });

    const result = await response.text();
    if (result.startsWith('https://pastebin.com/')) {
      return result.split('/').pop(); // Extract paste ID
    } else {
      console.error('Pastebin API error:', result);
      return null;
    }
  } catch (error) {
    console.error('Error creating paste:', error);
    return null;
  }
}
