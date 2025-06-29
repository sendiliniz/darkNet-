# DarkNet Chat Application

A modern, real-time chat application with a sleek dark theme and advanced features.

## Features

- 🌐 Real-time messaging with Socket.IO
- 🎨 Beautiful dark-themed UI with glass morphism effects
- 👥 User authentication and registration
- 🏠 Multiple chat servers/channels
- 👑 Admin controls and moderation
- 🔊 Voice chat capabilities
- 📱 Responsive design
- 🎵 Sound effects and notifications
- 💬 Message reactions and threads
- 📌 Message pinning
- ✏️ Message editing and deletion
- 👤 User profiles and status
- 🔐 Persistent data storage via Pastebin API

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/darknet-chat.git
cd darknet-chat
```

2. Install dependencies:
```bash
npm install
```

3. Start the server:
```bash
npm start
```

4. Open your browser and navigate to `http://localhost:5000`

## Configuration

### Environment Variables

Create a `.env` file in the root directory (optional):
```
PORT=5000
PASTEBIN_API_KEY=your_pastebin_api_key_here
```


## Usage

### Getting Started

1. Open the application in your browser
2. Register a new account or log in with existing credentials
3. Choose a username and avatar
4. Join different servers/channels
5. Start chatting!

### Features Guide

- **Servers**: Join different themed chat rooms (general, games, tech, music, etc.)
- **Voice Chat**: Click the voice call button to start voice conversations
- **Reactions**: React to messages with emojis
- **Threads**: Create threaded conversations from any message
- **Admin Commands**: 
  - `/kick [username]` - Kick a user
  - `/ban [username]` - Ban a user
  - `/announce [message]` - Send announcement
  - `/clear` - Clear chat history

## API Endpoints

- `GET /` - Main application
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `GET /auth/verify` - Verify authentication
- `GET /health` - Health check
- `GET /stats` - Server statistics
- `GET /api/servers` - Get all servers

## Socket Events

### Client to Server
- `set_username` - Set user identity
- `join_server` - Join a chat server
- `send_message` - Send a message
- `create_server` - Create new server
- `voice_*` - Voice chat events

### Server to Client
- `chat_message` - Receive messages
- `online_users_updated` - User list updates
- `server_created` - New server notifications
- `voice_*` - Voice chat events

## Technology Stack

- **Backend**: Node.js, Express.js, Socket.IO
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Storage**: Pastebin API for persistence
- **Real-time**: WebSocket connections
- **Voice**: WebRTC for peer-to-peer audio

## File Structure

```
darknet-chat/
├── server.js          # Main server file
├── index.html         # Main chat interface
├── login.html         # Login page
├── register.html      # Registration page
├── package.json       # Dependencies
├── README.md          # This file
└── .gitignore        # Git ignore rules
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Deployment

### Replit (Recommended)
1. Import this repository to Replit
2. The app will automatically configure and run
3. Use the provided URL to access your chat application

### Other Platforms
Make sure to:
- Set `PORT` environment variable if required
- Bind to `0.0.0.0` instead of `localhost`
- Configure WebSocket support

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the PORT in server.js or kill existing processes
2. **WebSocket connection failed**: Ensure WebSocket support is enabled
3. **Voice chat not working**: Check browser permissions for microphone access

### Browser Compatibility

- Chrome/Chromium (recommended)
- Firefox
- Safari
- Edge

## Support

If you encounter any issues or have questions, please open an issue on GitHub.
