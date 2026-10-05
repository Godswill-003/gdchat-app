const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);

// Configured with CORS allowance for global internet traffic
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

app.use(express.static(path.join(__dirname, "public")));

io.on("connection", (socket) => {
    console.log("User Connected to Global Network: " + socket.id);

    // Listens for WhatsApp style chats globally
    socket.on("chat message", (data) => {
        io.emit("chat message", data);
    });

    socket.on("disconnect", () => {
        console.log("User Disconnected: " + socket.id);
    });
});

// Crucial fix: Pulls the dynamic network port from online servers like Render
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log("🚀 GDChat Internet Server Online on Port " + PORT);
});
