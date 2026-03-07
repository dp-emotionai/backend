import { Server } from "socket.io"

let io

export function initSocket(server) {
    io = new Server(server, {
        cors: { origin: "*" },
    })

    io.on("connection", (socket) => {
        console.log("User connected", socket.id)

        socket.on("joinRoom", (roomId) => {
            socket.join(roomId)
        })

        socket.on("sendMessage", (data) => {
            io.to(data.roomId).emit("receiveMessage", data)
        })

        socket.on("typing", (data) => {
            io.to(data.roomId).emit("typing", data)
        })

        socket.on("video-signal", (data) => {
            io.to(data.roomId).emit("video-signal", data)
        })

        socket.on("disconnect", () => {
            console.log("User disconnected", socket.id)
        })
    })

    return io
}

export function getIO() {
    if (!io) {
        throw new Error("Socket.IO not initialized. Call initSocket(server) first.")
    }
    return io
}
