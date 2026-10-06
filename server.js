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
    res.sendFile(path.join(__dirname, 'public', 'appview.html'));
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
// 📝 SQLITE REGISTRATION ROUTE
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required." });
        }

        // 1. Securely hash the password using your imported bcrypt
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // 2. Insert the user into your SQLite database
        const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
        db.run(sql, [username, hashedPassword], function (err) {
            if (err) {
                // If username already exists, SQLite throws a UNIQUE constraint error
                if (err.message.includes("UNIQUE")) {
                    return res.status(400).json({ error: "Username is already taken." });
                }
                console.error(err.message);
                return res.status(500).json({ error: "Database error during registration." });
            }
            
            res.status(201).json({ message: "Registration successful! You can log in now." });
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Something went wrong during registration." });
    }
});

// 🔑 SQLITE LOGIN ROUTE
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required." });
        }

        // 1. Look up the user in your SQLite database
        const sql = `SELECT * FROM users WHERE username = ?`;
        db.get(sql, [username], async (err, user) => {
            if (err) {
                console.error(err.message);
                return res.status(500).json({ error: "Database error during login." });
            }

            // If user doesn't exist
            if (!user) {
                return res.status(400).json({ error: "Invalid username or password." });
            }

            // 2. Compare entered password with the saved hashed password
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ error: "Invalid username or password." });
            }

            // Login success! Send back user info (excluding password)
            res.status(200).json({ 
                message: "Login successful!", 
                user: { id: user.id, username: user.username } 
            });
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Something went wrong during login." });
    }
});// ⚡ REAL-TIME CHAT EVENTS
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    // Listen for when a user joins the chat session
    socket.on('join_room', (username) => {
        socket.username = username;
        // Broadcast to everyone else that a new user joined
        socket.broadcast.emit('system_message', `${username} has joined the chat.`);
    });

        // Listen for incoming chat messages from a user
    socket.on('send_message', (data) => {
        const msgPayload = {
            sender: data.sender,
            message: data.message,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };

        // Broadcast the message to ALL connected users
        io.emit('receive_message', msgPayload);
    });

    // Handle user disconnecting
    socket.on('disconnect', () => {
        if (socket.username) {
            io.emit('system_message', `${socket.username} has left the chat.`);
        }
        console.log(`User disconnected: ${socket.id}`);
    });
});

// Start the server (Make sure this matches your port variable name)
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
