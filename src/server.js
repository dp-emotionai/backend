import express from "express";
import http from "http";
import cors from "cors";
import "dotenv/config";
import { Server } from "socket.io";

import authRoutes from "./routes/auth.js";
import userRoutes from "./routes/users.js";
import noteRoutes from "./routes/notes.js";
import documentRoutes from "./routes/documents.js";
import groupRoutes from "./routes/groups.js";
import roomRoutes from "./routes/rooms.js";
import sessionRoutes from "./routes/sessions.js";
import analyticsRoutes from "./routes/analytics.js";


const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

// ❗ БЕЗ /api
app.use("/auth", authRoutes);
app.use("/users", userRoutes);
app.use("/notes", noteRoutes);
app.use("/documents", documentRoutes);
app.use("/groups", groupRoutes);
app.use("/rooms", roomRoutes);
app.use("/sessions", sessionRoutes);
app.use("/analytics", analyticsRoutes);

const io = new Server(server, {
    cors: { origin: "*" }
});

io.on("connection", (socket) => {

    socket.on("joinRoom", (roomId) => {
        socket.join(roomId);
    });

    socket.on("sendMessage", (data) => {
        io.to(data.roomId).emit("receiveMessage", data);
    });

    socket.on("disconnect", () => {});
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});