import express from "express";
import http from "http";
import cors from "cors";
import "dotenv/config";
import { Server } from "socket.io";
import cookieParser from "cookie-parser";

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

app.use(
    cors({
        origin: true,
        credentials: true,
    })
);

app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static("uploads"));

app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/sessions", sessionRoutes);
app.use("/api/analytics", analyticsRoutes);
app.use("/api/rooms", roomRoutes);
app.use("/api/groups", groupRoutes);
app.use("/api/documents", documentRoutes);
app.use("/api/notes", noteRoutes);

const io = new Server(server, {
    cors: {
        origin: "*",
    },
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