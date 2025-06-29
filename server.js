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
    origin: process.env.NODE_ENV === 'production' ? true : "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000,
  upgradeTimeout: 30000,
  allowEIO3: true,
  allowUpgrades: true,
  perMessageDeflate: false
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

async function updatePaste(pasteId, content, title) {
  // Pastebin doesn't support updating, so create new paste
  return await createPaste(content, title);
}

async function getPasteContent(pasteId) {
  if (!pasteId) return null;

  try {
    const response = await fetch(`https://pastebin.com/raw/${pasteId}`);
    if (response.ok) {
      return await response.text();
    } else {
      console.error('Failed to fetch paste:', response.status);
      return null;
    }
  } catch (error) {
    console.error('Error fetching paste:', error);
    return null;
  }
}

// Load persistent data from Pastebin
async function loadPersistentData() {
  try {
    console.log('🔄 Loading data from Pastebin...');

    // Try to load users data (using a known paste ID if exists)
    if (USERS_PASTE_ID) {
      const usersContent = await getPasteContent(USERS_PASTE_ID);
      if (usersContent) {
        try {
          const usersData = JSON.parse(usersContent);
          Object.entries(usersData.data || {}).forEach(([key, value]) => {
            registeredUsers.set(key, value);
          });
          console.log(`📂 Loaded ${registeredUsers.size} registered users`);
        } catch (e) {
          console.error('Error parsing users data:', e);
        }
      }
    }

    // Try to load sessions data
    if (SESSIONS_PASTE_ID) {
      const sessionsContent = await getPasteContent(SESSIONS_PASTE_ID);
      if (sessionsContent) {
        try {
          const sessionsData = JSON.parse(sessionsContent);
          const now = new Date();
          let validSessions = 0;

          Object.entries(sessionsData.data || {}).forEach(([token, session]) => {
            const sessionAge = now - new Date(session.loginTime);
            // Keep sessions valid for 7 days
            if (sessionAge < 7 * 24 * 60 * 60 * 1000) {
              authSessions.set(token, session);
              validSessions++;
            }
          });
          console.log(`🔑 Loaded ${validSessions} active sessions`);
        } catch (e) {
          console.error('Error parsing sessions data:', e);
        }
      }
    }
  } catch (error) {
    console.error('Error loading persistent data:', error);
  }
}

// Save persistent data to Pastebin
async function savePersistentData() {
  try {
    console.log('💾 Saving data to Pastebin...');

    // Save users
    const usersObj = {
      timestamp: new Date().toISOString(),
      data: {}
    };
    registeredUsers.forEach((value, key) => {
      usersObj.data[key] = value;
    });

    const usersContent = JSON.stringify(usersObj, null, 2);
    const newUsersPasteId = await createPaste(usersContent, 'DarkNet_Users_Data');
    if (newUsersPasteId) {
      USERS_PASTE_ID = newUsersPasteId;
      console.log(`✅ Users data saved to paste: ${USERS_PASTE_ID}`);
    }

    // Save sessions
    const sessionsObj = {
      timestamp: new Date().toISOString(),
      data: {}
    };
    authSessions.forEach((value, key) => {
      sessionsObj.data[key] = value;
    });

    const sessionsContent = JSON.stringify(sessionsObj, null, 2);
    const newSessionsPasteId = await createPaste(sessionsContent, 'DarkNet_Sessions_Data');
    if (newSessionsPasteId) {
      SESSIONS_PASTE_ID = newSessionsPasteId;
      console.log(`✅ Sessions data saved to paste: ${SESSIONS_PASTE_ID}`);
    }
  } catch (error) {
    console.error('Error saving persistent data:', error);
  }
}

// Auto-save every 10 minutes (reduced frequency for Pastebin)
setInterval(savePersistentData, 10 * 60 * 1000);

// Load data on startup
loadPersistentData();

// Admin ID
const ADMIN_ID = "495485ifd[fd-r-405i405]r4=";

// Authentication functions
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function verifyToken(token) {
  return authSessions.get(token);
}

function createUser(username, email, password) {
  if (registeredUsers.has(username.toLowerCase())) {
    return { success: false, message: 'Username already exists' };
  }

  const hashedPassword = hashPassword(password);
  const userData = {
    username: username,
    email: email || '',
    password: hashedPassword,
    createdAt: new Date(),
    isAdmin: false,
    verified: true
  };

  registeredUsers.set(username.toLowerCase(), userData);

  // Save immediately after creating user (async, don't wait)
  savePersistentData().catch(err => console.error('Failed to save user data:', err));
  console.log(`👤 New user registered: ${username}`);

  return { success: true, user: userData };
}

function authenticateUser(username, password) {
  const user = registeredUsers.get(username.toLowerCase());
  if (!user) {
    return { success: false, message: 'User not found' };
  }

  const hashedPassword = hashPassword(password);
  if (user.password !== hashedPassword) {
    return { success: false, message: 'Invalid password' };
  }

  const token = generateToken();
  authSessions.set(token, {
    username: user.username,
    isAdmin: user.isAdmin,
    loginTime: new Date()
  });

  return { 
    success: true, 
    token: token, 
    username: user.username, 
    isAdmin: user.isAdmin 
  };
}

// Default roles
const defaultRoles = {
  'admin': { name: 'Admin', color: '#ff5555', permissions: ['ban', 'kick', 'manage_channels', 'manage_roles'] },
  'moderator': { name: 'Moderator', color: '#f1c40f', permissions: ['kick', 'manage_messages'] },
  'member': { name: 'Member', color: '#95a5a6', permissions: ['send_messages', 'read_messages'] },
  'guest': { name: 'Guest', color: '#7f8c8d', permissions: ['read_messages'] }
};

// Default servers
const defaultServers = ['general', 'games', 'random', 'tech', 'music'];
let validServers = [...defaultServers];

function addUserToServer(userId, serverName) {
  if (!serverRooms.has(serverName)) {
    serverRooms.set(serverName, new Set());
  }
  serverRooms.get(serverName).add(userId);
}

function removeUserFromServer(userId, serverName) {
  if (serverRooms.has(serverName)) {
    serverRooms.get(serverName).delete(userId);
  }
}

function removeUserFromAllServers(userId) {
  serverRooms.forEach((users, serverName) => {
    users.delete(userId);
  });
}

function getUserBySocketId(socketId) {
  return Array.from(activeUsers.values()).find(user => user.id === socketId);
}

function broadcastToServer(serverName, eventName, data) {
  io.to(serverName).emit(eventName, data);
}

function validateMessage(message) {
  if (!message || typeof message !== 'string') return false;
  if (message.length === 0 || message.length > 2000) return false;
  return true;
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input.trim().substring(0, 2000);
}

function getOnlineUsers(serverName) {
  if (!serverRooms.has(serverName)) {
    return [];
  }

  const userIds = Array.from(serverRooms.get(serverName));
  return userIds.map(userId => {
    const user = Array.from(activeUsers.values()).find(u => u.id === userId);
    const profile = getUserProfile(userId);
    return user ? { 
      id: user.id, 
      name: user.name, 
      avatar: user.avatar, 
      isAdmin: user.isAdmin,
      profile: profile 
    } : null;
  }).filter(user => user !== null);
}

function createServer(serverName, creatorId) {
  if (validServers.includes(serverName) || customServers.has(serverName)) {
    return false; // Server already exists
  }

  const creator = Array.from(activeUsers.values()).find(u => u.id === creatorId);
  if (!creator) return false;

  customServers.set(serverName, {
    name: serverName,
    creator: creator.name,
    createdAt: new Date(),
    icon: '🏠'
  });

  validServers.push(serverName);
  return true;
}

function getAllServers() {
  const servers = [];

  // Add default servers
  defaultServers.forEach(name => {
    servers.push({
      name,
      icon: getServerIcon(name),
      isDefault: true,
      onlineCount: getOnlineUsers(name).length
    });
  });

  // Add custom servers
  customServers.forEach((server, name) => {
    servers.push({
      name,
      icon: server.icon,
      isDefault: false,
      creator: server.creator,
      onlineCount: getOnlineUsers(name).length
    });
  });

  return servers;
}

function getServerIcon(serverName) {
  const icons = {
    'general': '💬',
    'games': '🎮',
    'random': '🎲',
    'tech': '💻',
    'music': '🎵'
  };
  return icons[serverName] || '🏠';
}

function createUserProfile(userId, userData) {
  const profile = {
    userId: userId,
    displayName: userData.name,
    username: userData.name,
    bio: '',
    status: 'online',
    customStatus: '',
    joinedAt: new Date(),
    avatar: userData.avatar,
    badges: userData.isAdmin ? ['👑 Admin'] : [],
    theme: 'auto',
    pronouns: '',
    location: '',
    website: '',
    birthday: '',
    favoriteColor: '#3b82f6',
    isAdmin: userData.isAdmin,
    nitro: false,
    boosts: 0
  };
  userProfiles.set(userId, profile);

  // Assign default role
  const defaultRole = userData.isAdmin ? 'admin' : 'member';
  if (!userRoles.has(userId)) {
    userRoles.set(userId, new Map());
  }
  validServers.forEach(server => {
    if (!userRoles.get(userId).has(server)) {
      userRoles.get(userId).set(server, defaultRole);
    }
  });

  return profile;
}

function createMessageThread(messageId, parentMessage, creator) {
  const thread = {
    id: messageId,
    parentMessage: parentMessage,
    creator: creator,
    createdAt: new Date(),
    messages: [],
    participants: new Set([creator])
  };
  messageThreads.set(messageId, thread);
  return thread;
}

function addReactionToMessage(messageId, emoji, userId) {
  if (!messageReactions.has(messageId)) {
    messageReactions.set(messageId, new Map());
  }

  const reactions = messageReactions.get(messageId);
  if (!reactions.has(emoji)) {
    reactions.set(emoji, new Set());
  }

  reactions.get(emoji).add(userId);
  return reactions;
}

function removeReactionFromMessage(messageId, emoji, userId) {
  if (!messageReactions.has(messageId)) return null;

  const reactions = messageReactions.get(messageId);
  if (reactions.has(emoji)) {
    reactions.get(emoji).delete(userId);
    if (reactions.get(emoji).size === 0) {
      reactions.delete(emoji);
    }
  }

  return reactions;
}

function getUserRole(userId, serverName) {
  if (!userRoles.has(userId)) return 'guest';
  if (!userRoles.get(userId).has(serverName)) return 'guest';
  return userRoles.get(userId).get(serverName);
}

function hasPermission(userId, serverName, permission) {
  const role = getUserRole(userId, serverName);
  return defaultRoles[role]?.permissions.includes(permission) || false;
}

function updateUserProfile(userId, updates) {
  const profile = userProfiles.get(userId);
  if (profile) {
    Object.assign(profile, updates);
    userProfiles.set(userId, profile);
    return profile;
  }
  return null;
}

function getUserProfile(userId) {
  return userProfiles.get(userId) || null;
}

function addMessageToHistory(serverName, messageData) {
  if (!messageHistory.has(serverName)) {
    messageHistory.set(serverName, []);
  }

  const history = messageHistory.get(serverName);
  history.push(messageData);

  // Keep only last 100 messages per server
  if (history.length > 100) {
    history.splice(0, history.length - 100);
  }

  messageHistory.set(serverName, history);
}

function getMessageHistory(serverName, limit = 50) {
  const history = messageHistory.get(serverName) || [];
  return history.slice(-limit);
}

function addTypingUser(serverName, username) {
  if (!typingUsers.has(serverName)) {
    typingUsers.set(serverName, new Set());
  }
  typingUsers.get(serverName).add(username);
}

function removeTypingUser(serverName, username) {
  if (typingUsers.has(serverName)) {
    typingUsers.get(serverName).delete(username);
  }
}

function getTypingUsers(serverName) {
  return Array.from(typingUsers.get(serverName) || []);
}

// Socket.IO connection handling
io.on("connection", (socket) => {
  console.log(`New connection: ${socket.id} from ${socket.handshake.address}`);

  let userData = null;
  let currentServers = new Set();

  // Add connection error handling
  socket.on('error', (error) => {
    console.error(`Socket error for ${socket.id}:`, error);
  });

  socket.on('connect_error', (error) => {
    console.error(`Connection error for ${socket.id}:`, error);
  });

  // Set username
  socket.on("set_username", (data, callback) => {
    const name = typeof data === 'string' ? data : data.name;
    const avatar = typeof data === 'object' ? data.avatar : null;

    if (!name || name.length < 2) {
      return callback({ 
        success: false, 
        message: "Username must be at least 2 characters long" 
      });
    }

    if (activeUsers.has(name)) {
      return callback({ 
        success: false, 
        message: "Username already taken!" 
      });
    }

    // Check if user entered admin ID
    const isAdmin = name === ADMIN_ID;
    let finalName = name;

    if (isAdmin) {
      finalName = "Admin";
      adminUsers.add(socket.id);
      console.log(`Admin user authenticated with ID: ${socket.id}`);
    }

    userData = { 
      id: socket.id,
      name: finalName, 
      avatar,
      isAdmin: isAdmin
    };

    activeUsers.set(finalName, userData);

    // Create user profile
    const profile = createUserProfile(socket.id, userData);

    console.log(`User ${finalName} registered${isAdmin ? ' (ADMIN)' : ''}`);

    callback({ success: true, isAdmin: isAdmin, profile: profile });
  });

  // Get all servers
  socket.on("get_servers", (callback) => {
    callback(getAllServers());
  });

  // Create server
  socket.on("create_server", (data, callback) => {
    if (!userData) {
      return callback({ success: false, message: "Not authenticated" });
    }

    const serverName = data.name.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');

    if (!serverName || serverName.length < 2 || serverName.length > 20) {
      return callback({ success: false, message: "Server name must be 2-20 characters, letters/numbers only" });
    }

    if (createServer(serverName, userData.id)) {
      io.emit("server_created", {
        name: serverName,
        icon: '🏠',
        creator: userData.name,
        isDefault: false,
        onlineCount: 0
      });
      callback({ success: true, serverName });
    } else {
      callback({ success: false, message: "Server name already exists" });
    }
  });

  // Get online users for server
  socket.on("get_online_users", (serverName, callback) => {
    const onlineUsers = getOnlineUsers(serverName);
    callback(onlineUsers);
  });

  // Join server
  socket.on("join_server", (serverName) => {
    if (!userData || !validServers.includes(serverName)) {
      return;
    }

    socket.join(serverName);
    currentServers.add(serverName);
    addUserToServer(userData.id, serverName);

    console.log(`${userData.name} joined #${serverName}`);

    // Send message history to the joining user
    const history = getMessageHistory(serverName);
    socket.emit("message_history", { server: serverName, messages: history });

    const joinMessage = {
      id: Date.now() + Math.random().toString(36).substr(2, 9),
      server: serverName,
      user: "System",
      message: `${userData.name} joined #${serverName}`,
      timestamp: new Date()
    };

    io.to(serverName).emit("chat_message", joinMessage);
    addMessageToHistory(serverName, joinMessage);

    // Broadcast updated online users to all users in the server
    const onlineUsers = getOnlineUsers(serverName);
    io.to(serverName).emit("online_users_updated", { server: serverName, users: onlineUsers });

    // Update server list for all users
    io.emit("servers_updated", getAllServers());
  });

  // Leave server
  socket.on("leave_server", (serverName) => {
    if (!userData || !validServers.includes(serverName)) {
      return;
    }

    socket.leave(serverName);
    currentServers.delete(serverName);
    removeUserFromServer(userData.id, serverName);

    io.to(serverName).emit("chat_message", {
      server: serverName,
      user: "System",
      message: `${userData.name} left #${serverName}`
    });

    // Broadcast updated online users to remaining users in the server
    const onlineUsers = getOnlineUsers(serverName);
    io.to(serverName).emit("online_users_updated", { server: serverName, users: onlineUsers });

    // Update server list for all users
    io.emit("servers_updated", getAllServers());
  });

  // Update avatar
  socket.on("update_avatar", (data) => {
    if (!userData || !data.avatar) {
      return;
    }

    userData.avatar = data.avatar;
    activeUsers.set(userData.name, userData);

    // Update profile avatar
    updateUserProfile(userData.id, { avatar: data.avatar });

    console.log(`${userData.name} updated their avatar`);
  });

  // Get user profile
  socket.on("get_profile", (targetUserId, callback) => {
    if (!userData) {
      return callback({ success: false, message: "Not authenticated" });
    }

    const profile = getUserProfile(targetUserId || userData.id);
    if (profile) {
      callback({ success: true, profile: profile });
    } else {
      callback({ success: false, message: "Profile not found" });
    }
  });

  // Set user status
  socket.on("set_status", (statusData, callback) => {
    if (!userData) {
      return callback({ success: false, message: "Not authenticated" });
    }

    const allowedStatuses = ['online', 'away', 'busy', 'invisible'];
    if (!allowedStatuses.includes(statusData.status)) {
      return callback({ success: false, message: "Invalid status" });
    }

    const updates = {
      status: statusData.status,
      customStatus: sanitizeInput(statusData.customStatus || '')
    };

    const updatedProfile = updateUserProfile(userData.id, updates);
    if (updatedProfile) {
      // Broadcast status update to all servers the user is in
      currentServers.forEach(serverName => {
        const onlineUsers = getOnlineUsers(serverName);
        io.to(serverName).emit("online_users_updated", { server: serverName, users: onlineUsers });
      });

      callback({ success: true, profile: updatedProfile });
    } else {
      callback({ success: false, message: "Failed to update status" });
    }
  });

  // Get message history
  socket.on("get_message_history", (serverName, callback) => {
    if (!userData || !validServers.includes(serverName)) {
      return callback({ success: false, message: "Invalid server" });
    }

    const history = getMessageHistory(serverName);
    callback({ success: true, messages: history });
  });

  // Update user profile
  socket.on("update_profile", (profileData, callback) => {
    if (!userData) {
      return callback({ success: false, message: "Not authenticated" });
    }

    // Validate profile data
    const allowedUpdates = [
      'displayName', 'bio', 'customStatus', 'pronouns', 
      'location', 'website', 'birthday', 'favoriteColor', 'theme'
    ];

    const updates = {};
    for (const key of allowedUpdates) {
      if (profileData.hasOwnProperty(key)) {
        if (key === 'displayName' && (!profileData[key] || profileData[key].length < 1 || profileData[key].length > 32)) {
          return callback({ success: false, message: "Display name must be 1-32 characters" });
        }
        if (key === 'bio' && profileData[key] && profileData[key].length > 200) {
          return callback({ success: false, message: "Bio must be less than 200 characters" });
        }
        if (key === 'customStatus' && profileData[key] && profileData[key].length > 100) {
          return callback({ success: false, message: "Custom status must be less than 100 characters" });
        }
        updates[key] = profileData[key];
      }
    }

    const updatedProfile = updateUserProfile(userData.id, updates);
    if (updatedProfile) {
      // Update display name in active users if changed
      if (updates.displayName && updates.displayName !== userData.name) {
        activeUsers.delete(userData.name);
        userData.name = updates.displayName;
        activeUsers.set(userData.name, userData);
      }

      callback({ success: true, profile: updatedProfile });

      // Broadcast profile update to current servers
      currentServers.forEach(serverName => {
        const onlineUsers = getOnlineUsers(serverName);
        io.to(serverName).emit("online_users_updated", { server: serverName, users: onlineUsers });
      });
    } else {
      callback({ success: false, message: "Failed to update profile" });
    }
  });

  // Send message
  socket.on("send_message", ({ server, message, avatar, replyTo, threadId }) => {
    if (!userData || !validServers.includes(server) || !currentServers.has(server)) {
      socket.emit('error_message', { message: 'You are not in this server.' });
      return;
    }

    if (!hasPermission(userData.id, server, 'send_messages')) {
      socket.emit('error_message', { message: 'You do not have permission to send messages in this server.' });
      return;
    }

    const trimmedMessage = sanitizeInput(message);

    if (!validateMessage(trimmedMessage)) {
      socket.emit('error_message', { message: 'Invalid message. Messages must be 1-2000 characters.' });
      return;
    }

    // Check for admin commands
    if (userData.isAdmin && trimmedMessage.startsWith('/')) {
      handleAdminCommand(trimmedMessage, server);
      return;
    }

    const messageId = Date.now() + Math.random().toString(36).substr(2, 9);
    const messageData = {
      id: messageId,
      server,
      user: userData.name,
      message: trimmedMessage,
      avatar: avatar || userData.avatar,
      isAdmin: userData.isAdmin,
      timestamp: new Date(),
      replyTo: replyTo || null,
      threadId: threadId || null,
      reactions: new Map(),
      edited: false,
      pinned: false
    };

    // If this is a thread message
    if (threadId && messageThreads.has(threadId)) {
      const thread = messageThreads.get(threadId);
      thread.messages.push(messageData);
      thread.participants.add(userData.id);
      messageThreads.set(threadId, thread);

      io.to(server).emit("thread_message", { threadId, message: messageData });
    } else {
      io.to(server).emit("chat_message", messageData);
      addMessageToHistory(server, messageData);
    }

    // Remove user from typing indicators
    removeTypingUser(server, userData.name);
    const typingUsersList = getTypingUsers(server);
    io.to(server).emit("typing_updated", { server, users: typingUsersList });

    console.log(`Message from ${userData.name}${userData.isAdmin ? ' (ADMIN)' : ''} in #${server}: ${trimmedMessage.substring(0, 50)}${trimmedMessage.length > 50 ? '...' : ''}`);
  });

  // Create thread
  socket.on("create_thread", ({ messageId, parentMessage, server }) => {
    if (!userData || !validServers.includes(server) || !currentServers.has(server)) {
      return;
    }

    if (!hasPermission(userData.id, server, 'send_messages')) {
      return;
    }

    const thread = createMessageThread(messageId, parentMessage, userData.id);
    io.to(server).emit("thread_created", { 
      threadId: messageId, 
      thread: {
        ...thread,
        creator: userData.name,
        participants: Array.from(thread.participants)
      }
    });
  });

  // Add reaction
  socket.on("add_reaction", ({ messageId, emoji, server }) => {
    if (!userData || !validServers.includes(server) || !currentServers.has(server)) {
      return;
    }

    const reactions = addReactionToMessage(messageId, emoji, userData.id);
    const reactionData = {};
    reactions.forEach((users, emoji) => {
      reactionData[emoji] = users.size;
    });

    io.to(server).emit("reaction_added", { 
      messageId, 
      emoji, 
      userId: userData.id,
      userName: userData.name,
      reactions: reactionData
    });
  });

  // Remove reaction
  socket.on("remove_reaction", ({ messageId, emoji, server }) => {
    if (!userData || !validServers.includes(server) || !currentServers.has(server)) {
      return;
    }

    const reactions = removeReactionFromMessage(messageId, emoji, userData.id);
    if (reactions) {
      const reactionData = {};      reactions.forEach((users, emoji) => {
        reactionData[emoji] = users.size;
      });

      io.to(server).emit("reaction_removed", { 
        messageId, 
        emoji, 
        userId: userData.id,
        reactions: reactionData
      });
    }
  });

  // Pin message
  socket.on("pin_message", ({ messageId, server }) => {
    if (!userData || !validServers.includes(server) || !currentServers.has(server)) {
      return;
    }

    if (!hasPermission(userData.id, server, 'manage_messages')) {
      return;
    }

    if (!pinnedMessages.has(server)) {
      pinnedMessages.set(server, new Set());
    }

    pinnedMessages.get(server).add(messageId);
    io.to(server).emit("message_pinned", { messageId, server });
  });

  // Get pinned messages
  socket.on("get_pinned_messages", (server, callback) => {
    if (!userData || !validServers.includes(server)) {
      return callback([]);
    }

    const pinned = pinnedMessages.get(server) || new Set();
    callback(Array.from(pinned));
  });

  // Edit message
  socket.on("edit_message", ({ messageId, newMessage, server }) => {
    if (!userData || !validServers.includes(server) || !currentServers.has(server)) {
      return;
    }

    const trimmedMessage = newMessage.trim().substring(0, 2000);
    io.to(server).emit("message_edited", { 
      messageId, 
      newMessage: trimmedMessage,
      editedBy: userData.name,
      editedAt: new Date()
    });
  });

  // Delete message
  socket.on("delete_message", ({ messageId, server }) => {
    if (!userData || !validServers.includes(server) || !currentServers.has(server)) {
      return;
    }

    if (!hasPermission(userData.id, server, 'manage_messages')) {
      return;
    }

    io.to(server).emit("message_deleted", { messageId, server });
  });

  // Send file
  socket.on("send_file", ({ server, fileData, fileName, fileType }) => {
    if (!userData || !validServers.includes(server) || !currentServers.has(server)) {
      return;
    }

    if (!hasPermission(userData.id, server, 'send_messages')) {
      return;
    }

    const messageId = Date.now() + Math.random().toString(36).substr(2, 9);
    const messageData = {
      id: messageId,
      server,
      user: userData.name,
      message: `📎 **${fileName}**`,
      avatar: userData.avatar,
      isAdmin: userData.isAdmin,
      timestamp: new Date(),
      file: {
        name: fileName,
        type: fileType,
        data: fileData
      },
      reactions: new Map(),
      edited: false,
      pinned: false
    };

    io.to(server).emit("chat_message", messageData);
  });

  // Admin command handler
  function handleAdminCommand(command, server) {
    const args = command.split(' ');
    const cmd = args[0].toLowerCase();

    switch (cmd) {
      case '/kick':
        if (args[1]) {
          const targetUser = args[1];
          kickUser(targetUser, server);
        }
        break;
      case '/ban':
        if (args[1]) {
          const targetUser = args[1];
          banUser(targetUser, server);
        }
        break;
      case '/announce':
        const announcement = args.slice(1).join(' ');
        if (announcement) {
          io.to(server).emit("chat_message", {
            server,
            user: "🚨 ADMIN ANNOUNCEMENT",
            message: announcement,
            isAnnouncement: true
          });
        }
        break;
      case '/clear':
        io.to(server).emit("clear_chat");
        break;
      default:
        socket.emit("chat_message", {
          server,
          user: "System",
          message: "Unknown admin command. Available: /kick [user], /ban [user], /announce [message], /clear"
        });
    }
  }

  function kickUser(username, server) {
    const userToKick = Array.from(activeUsers.values()).find(user => user.name === username);
    if (userToKick) {
      const kickSocket = io.sockets.sockets.get(userToKick.id);
      if (kickSocket) {
        kickSocket.emit("kicked", { reason: "Kicked by admin" });
        kickSocket.disconnect();
        io.to(server).emit("chat_message", {
          server,
          user: "System",
          message: `${username} was kicked by an admin`
        });
      }
    }
  }

  function banUser(username, server) {
    const userToBan = Array.from(activeUsers.values()).find(user => user.name === username);
    if (userToBan) {
      const banSocket = io.sockets.sockets.get(userToBan.id);
      if (banSocket) {
        banSocket.emit("banned", { reason: "Banned by admin" });
        banSocket.disconnect();
        io.to(server).emit("chat_message", {
          server,
          user: "System",
          message: `${username} was banned by an admin`
        });
      }
    }
  }

  // WebRTC signaling for voice chat
  socket.on("voice_offer", (data) => {
    socket.to(data.target).emit("voice_offer", {
      offer: data.offer,
      from: socket.id,
      fromUser: userData ? userData.name : "Unknown"
    });
  });

  socket.on("voice_answer", (data) => {
    socket.to(data.target).emit("voice_answer", {
      answer: data.answer,
      from: socket.id
    });
  });

  socket.on("voice_ice_candidate", (data) => {
    socket.to(data.target).emit("voice_ice_candidate", {
      candidate: data.candidate,
      from: socket.id
    });
  });

  socket.on("voice_call_user", (data) => {
    socket.to(data.target).emit("incoming_voice_call", {
      from: socket.id,
      fromUser: userData ? userData.name : "Unknown",
      server: data.server
    });
  });

  socket.on("voice_call_response", (data) => {
    socket.to(data.target).emit("voice_call_response", {
      accepted: data.accepted,
      from: socket.id
    });
  });

  socket.on("voice_call_end", (data) => {
    socket.to(data.target).emit("voice_call_ended", {
      from: socket.id
    });
  });

  // Handle typing indicators
  socket.on("typing_start", (data) => {
    if (!userData || !validServers.includes(data.server) || !currentServers.has(data.server)) return;

    addTypingUser(data.server, userData.name);
    const typingUsersList = getTypingUsers(data.server);

    socket.to(data.server).emit("typing_updated", {
      server: data.server,
      users: typingUsersList
    });
  });

  socket.on("typing_stop", (data) => {
    if (!userData || !validServers.includes(data.server)) return;

    removeTypingUser(data.server, userData.name);
    const typingUsersList = getTypingUsers(data.server);

    socket.to(data.server).emit("typing_updated", {
      server: data.server,
      users: typingUsersList
    });
  });

  // Handle disconnection
  socket.on("disconnect", (reason) => {
    console.log(`Socket ${socket.id} disconnected: ${reason}`);

    if (userData) {
      activeUsers.delete(userData.name);

      // Remove from admin users if applicable
      if (userData.isAdmin) {
        adminUsers.delete(socket.id);
      }

      // Clean up user profile
      userProfiles.delete(userData.id);
      userRoles.delete(userData.id);

      currentServers.forEach(serverName => {
        removeUserFromServer(userData.id, serverName);

        // Emit typing stop for this user
        socket.to(serverName).emit("typing_stop", {
          server: serverName,
          user: userData.name
        });

        io.to(serverName).emit("chat_message", {
          server: serverName,
          user: "System",
          message: `${userData.name} disconnected`
        });

        // Broadcast updated online users
        const onlineUsers = getOnlineUsers(serverName);
        io.to(serverName).emit("online_users_updated", { server: serverName, users: onlineUsers });
      });

      // Update server list for all users
      io.emit("servers_updated", getAllServers());

      console.log(`User ${userData.name}${userData.isAdmin ? ' (ADMIN)' : ''} disconnected (${reason})`);
    }
  });

  // Handle socket errors gracefully
  socket.on('error', (error) => {
    console.error(`Socket ${socket.id} error:`, error);
    if (userData) {
      console.log(`Cleaning up user ${userData.name} due to socket error`);
      activeUsers.delete(userData.name);
      userProfiles.delete(userData.id);
      removeUserFromAllServers(userData.id);
    }
  });
});

const PORT = process.env.PORT || 5000;
const HOST = process.env.NODE_ENV === 'production' ? '0.0.0.0' : "0.0.0.0";

// Add better error handling
server.on('error', (error) => {
  console.error('Server error:', error);
});

// Add graceful shutdown
process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`🚀 Server running on http://${HOST}:${PORT}`);
  console.log(`📡 WebSocket server ready for connections`);
  console.log(`🌐 Access your app at: https://${process.env.REPL_SLUG || 'your-repl'}.${process.env.REPL_OWNER || 'username'}.repl.co`);

  // Log server stats every 30 seconds
  setInterval(() => {
    const connectedSockets = io.engine.clientsCount;
    const activeUserCount = activeUsers.size;
    const totalServers = validServers.length;

    console.log(`📊 Stats: ${connectedSockets} connections, ${activeUserCount} users, ${totalServers} servers`);
  }, 30000);
});

// Add health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    connections: io.engine.clientsCount,
    activeUsers: activeUsers.size,
    servers: validServers.length
  });
});

// Add server statistics endpoint
app.get('/stats', (req, res) => {
  const serverStats = {};
  validServers.forEach(serverName => {
    const onlineUsers = getOnlineUsers(serverName);
    const messageCount = messageHistory.get(serverName)?.length || 0;
    serverStats[serverName] = {
      onlineUsers: onlineUsers.length,
      totalMessages: messageCount,
      users: onlineUsers.map(u => ({
        name: u.name,
        isAdmin: u.isAdmin,
        status: u.profile?.status || 'online'
      }))
    };
  });

  res.json({
    timestamp: new Date().toISOString(),
    totalConnections: io.engine.clientsCount,
    totalActiveUsers: activeUsers.size,
    totalServers: validServers.length,
    servers: serverStats,
    customServers: Array.from(customServers.keys()),
    uptime: process.uptime()
  });
});

// Add simple API to get all servers
app.get('/api/servers', (req, res) => {
  res.json({
    success: true,
    servers: getAllServers()
  });
});
