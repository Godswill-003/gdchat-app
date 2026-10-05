const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { 
    cors: { origin: "*" } 
});

app.use(express.json());
// Strictly serve static assets from the public directory subfolder layout
app.use(express.static(path.join(__dirname, 'public')));

// 1. Initialize SQLite Database
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'), (err) => {
    if (err) console.error('Database connection error:', err);
    else console.log('Connected to SQLite Database.');
});

// 2. Create tables permanently
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        text TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const onlineUsers = new Map();

// 3. Secure Auth HTTP Routes
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: "Username already exists" });
            res.json({ success: true });
        });
    } catch { res.status(500).json({ error: "Server error" }); }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "User not found" });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: "Wrong password" });
        res.json({ success: true, username: user.username });
    });
});

// Strictly serves the core dark template out of the public subfolder path
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 4. WebSockets Engine
io.on('connection', (socket) => {
    let currentUsername = "";

    socket.on('registerOnlineUser', (username) => {
        currentUsername = username;
        onlineUsers.set(username, socket.id);
        io.emit('updateUserList', Array.from(onlineUsers.keys()));
    });

    socket.on('loadHistory', (targetUser) => {
        db.all(`SELECT * FROM messages WHERE 
            (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) 
            ORDER BY timestamp ASC`, 
            [currentUsername, targetUser, targetUser, currentUsername], (err, rows) => {
                if (!err) socket.emit('chatHistory', rows);
            });
    });

    socket.on('privateMessage', (data) => {
        const { receiver, text } = data;
        db.run(`INSERT INTO messages (sender, receiver, text) VALUES (?, ?, ?)`, 
            [currentUsername, receiver, text], function(err) {
                if (err) return;
                const msgPayload = { id: this.lastID, sender: currentUsername, receiver, text };
                socket.emit('incomingMessage', msgPayload);
                const receiverSocketId = onlineUsers.get(receiver);
                if (receiverSocketId) {
                    io.to(receiverSocketId).emit('incomingMessage', msgPayload);
                }
            });
    });

    socket.on('deleteMessage', (messageId) => {
        db.run(`DELETE FROM messages WHERE id = ? AND sender = ?`, [messageId, currentUsername], (err) => {
            if (!err) io.emit('messageDeleted', messageId);
        });
    });

    socket.on('disconnect', () => {
        if (currentUsername) {
            onlineUsers.delete(currentUsername);
            io.emit('updateUserList', Array.from(onlineUsers.keys()));
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log(`GDChat Engine live on port ${PORT}`));
