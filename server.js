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

// Middleware configuration parsing setups
app.use(express.json({ limit: '10mb' })); 
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite database instance link
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error("Database connection failure:", err.message);
    else console.log("Connected to SQLite secure storage database.");
});

// 📊 UPGRADED SCHEMA: Supports Phone, Email, Avatar data, and active OTP caching tracking keys
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
});

// 📝 1. NEW REGISTRATION ROUTE (Handles Email/Phone parsing + Avatar saving)
app.post('/register', async (req, res) => {
    try {
        const { username, contact, password, type, avatar } = req.body;

        if (!username || !contact || !password || !type) {
            return res.status(400).json({ error: "All account credential parameters are required." });
        }

        // Hashing structural verification layers
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generate a random WhatsApp-style 4-digit OTP code string sequence 
        const generationOtp = Math.floor(1000 + Math.random() * 9000).toString();

        const sql = `INSERT INTO users (username, contact, type, password, avatar, current_otp) VALUES (?, ?, ?, ?, ?, ?)`;
        
        db.run(sql, [username, contact, type, hashedPassword, avatar || "", generationOtp], function (err) {
            if (err) {
                if (err.message.includes("UNIQUE")) {
                    return res.status(400).json({ error: "Username or contact info already associated with an account." });
                }
                return res.status(500).json({ error: "Database exception storage failure configuration." });
            }

            // 🚀 SECURITY CONSOLE LOGGER: Read this code within your Render terminal stream log lines to pass checks instantly!
            console.log(`\n===============================================\n[OTP SYSTEM DISPATCH] To user: ${username}\nVerification destination: ${contact}\n👉 LIVE CONFIRMATION OTP ACCESS KEY: ${generationOtp}\n===============================================\n`);

            res.status(201).json({ message: "Registration pass successful. Processing verification step." });
        });
    } catch (err) {
        res.status(500).json({ error: "System initialization operational collapse failure." });
    }
});

// 🔑 2. NEW INTERACTIVE LOGIN ROUTE (Validates identifier string fields + Updates OTP)
app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;

        if (!identifier || !password) {
            return res.status(400).json({ error: "All login parameters are required." });
        }

        const sql = `SELECT * FROM users WHERE contact = ? OR username = ?`;
        db.get(sql, [identifier, identifier], async (err, user) => {
            if (err) return res.status(500).json({ error: "Database error during pipeline lookup lookup processing query." });
            if (!user) return res.status(400).json({ error: "No account matched those credentials." });

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(400).json({ error: "Incorrect password selection." });

            // User verification passed password layer. Generate dynamic fresh code parameters.
            const freshOtp = Math.floor(1000 + Math.random() * 9000).toString();
            
            db.run(`UPDATE users SET current_otp = ? WHERE id = ?`, [freshOtp, user.id], (updateErr) => {
                if (updateErr) return res.status(500).json({ error: "Failed to allocate validation tokens." });

                // 🚀 SECURITY CONSOLE LOGGER: Read this code within your Render terminal stream log lines to pass checks instantly!
                console.log(`\n===============================================\n[OTP SYSTEM DISPATCH] Welcome back user: ${user.username}\nVerification destination: ${user.contact}\n👉 LIVE CONFIRMATION OTP ACCESS KEY: ${freshOtp}\n===============================================\n`);

                res.status(200).json({ message: "Password match confirmed. Transitioning to safety challenge layer." });
            });
        });
    } catch (err) {
        res.status(500).json({ error: "Login routing interface runtime exception." });
    }
});

// 💬 3. WHATSAPP OTP VERIFICATION INTERCEPTOR ROUTE
app.post('/verify-otp', (req, res) => {
    const { identifier, code } = req.body;

    if (!identifier || !code) {
        return res.status(400).json({ error: "Missing verification payload data signatures." });
    }

    const sql = `SELECT * FROM users WHERE (contact = ? OR username = ?) AND current_otp = ?`;
    db.get(sql, [identifier, identifier, code], (err, user) => {
        if (err) return res.status(500).json({ error: "Verification processing platform system error." });
        if (!user) return res.status(400).json({ error: "Invalid verification code sequence. Please check your developer console logs." });

        // Authentication finalized. Clear cached token state for session safety.
        db.run(`UPDATE users SET current_otp = NULL WHERE id = ?`, [user.id]);

        res.status(200).json({
            message: "Authentication cleared successfully!",
            user: { id: user.id, username: user.username, avatar: user.avatar }
        });
    });
});

// ⚡ REAL-TIME WEBSOCKET ROUTING GRAPH CHANNELS
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    socket.on('join_room', (username) => {
        socket.username = username;
        socket.broadcast.emit('system_message', `${username} has joined the chat.`);
    });

    socket.on('send_message', (data) => {
        const msgPayload = {
            sender: data.sender,
            message: data.message,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };
        io.emit('receive_message', msgPayload);
    });

    socket.on('disconnect', () => {
        if (socket.username) {
            io.emit('system_message', `${socket.username} has left the chat.`);
        }
        console.log(`User disconnected: ${socket.id}`);
    });
});

// Allocate server ports dynamically
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running securely on port ${PORT}`);
});
