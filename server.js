const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" }
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error("Database connection failure:", err.message);
});

// Initialize Unified Storage Schemas
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        contact TEXT UNIQUE,
        type TEXT,
        password TEXT,
        avatar TEXT,
        current_otp TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        recipient TEXT,
        message TEXT,
        timestamp TEXT,
        is_ephemeral INTEGER DEFAULT 0
    )`);
});

// Onboarding & Challenge Authentication Routes
app.post('/register', async (req, res) => {
    try {
        const { username, contact, password, type, avatar } = req.body;
        if (!username || !contact || !password) return res.status(400).json({ error: "Missing parameters." });
        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const generationOtp = Math.floor(1000 + Math.random() * 9000).toString();

        const sql = `INSERT INTO users (username, contact, type, password, avatar, current_otp) VALUES (?, ?, ?, ?, ?, ?)`;
        db.run(sql, [username, contact, type, hashedPassword, avatar || "", generationOtp], function (err) {
            if (err) return res.status(400).json({ error: "Username or contact info already taken." });
            console.log(`\n===============================================\n👉 LIVE CONFIRMATION OTP ACCESS KEY: ${generationOtp}\n===============================================\n`);
            res.status(201).json({ message: "Registration successful." });
        });
    } catch (err) { res.status(500).json({ error: "Server error." }); }
});

app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const sql = `SELECT * FROM users WHERE contact = ? OR username = ?`;
        db.get(sql, [identifier, identifier], async (err, user) => {
            if (!user) return res.status(400).json({ error: "No account matched those credentials." });
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(400).json({ error: "Incorrect password." });

            const freshOtp = Math.floor(1000 + Math.random() * 9000).toString();
            db.run(`UPDATE users SET current_otp = ? WHERE id = ?`, [freshOtp, user.id], () => {
                console.log(`\n===============================================\n👉 LIVE CONFIRMATION OTP ACCESS KEY: ${freshOtp}\n===============================================\n`);
                res.status(200).json({ message: "OTP challenge dispatched." });
            });
        });
    } catch (err) { res.status(500).json({ error: "Server error." }); }
});

app.post('/verify-otp', (req, res) => {
    const { identifier, code } = req.body;
    const sql = `SELECT * FROM users WHERE (contact = ? OR username = ?) AND current_otp = ?`;
    db.get(sql, [identifier, identifier, code], (err, user) => {
        if (!user) return res.status(400).json({ error: "Invalid verification code." });
        db.run(`UPDATE users SET current_otp = NULL WHERE id = ?`, [user.id]);
        res.status(200).json({ user: { id: user.id, username: user.username, avatar: user.avatar } });
    });
});

// Load Historical Data Pipelines
app.get('/api/users', (req, res) => {
    db.all(`SELECT id, username, avatar FROM users`, [], (err, rows) => {
        res.status(200).json(rows);
    });
});

app.get('/api/messages', (req, res) => {
    db.all(`SELECT sender, recipient, message, timestamp, is_ephemeral FROM messages ORDER BY id ASC`, [], (err, rows) => {
        res.status(200).json(rows);
    });
});

// Real-Time Signal Channels
const globalOnlineDirectory = new Map();

io.on('connection', (socket) => {
    socket.on('join_room', (username) => {
        socket.username = username;
        globalOnlineDirectory.set(username, socket.id);
        io.emit('online_directory_update', Array.from(globalOnlineDirectory.keys()));
    });

    socket.on('send_message', (data) => {
        const payload = {
            sender: data.sender,
            recipient: data.recipient,
            message: data.message,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            is_ephemeral: data.is_ephemeral || 0
        };
        db.run(`INSERT INTO messages (sender, recipient, message, timestamp, is_ephemeral) VALUES (?, ?, ?, ?, ?)`, 
            [payload.sender, payload.recipient, payload.message, payload.timestamp, payload.is_ephemeral]);
        io.emit('receive_message', payload);
    });

    socket.on('typing_state', (data) => {
        socket.broadcast.emit('typing_relay', data);
    });

    socket.on('sync_video_state', (data) => {
        socket.broadcast.emit('video_relay', data);
    });

    socket.on('disconnect', () => {
        if (socket.username) {
            globalOnlineDirectory.delete(socket.username);
            io.emit('online_directory_update', Array.from(globalOnlineDirectory.keys()));
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running secure on port ${PORT}`));
