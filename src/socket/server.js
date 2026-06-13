import { Server } from "socket.io"
import jwt from "jsonwebtoken"
import prisma from "../utils/prisma.js"

let io

function getAllowedOrigins() {
    const configured = String(
        process.env.WS_ALLOWED_ORIGINS ||
        process.env.CORS_ORIGIN ||
        ""
    )
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean)

    return Array.from(
        new Set([
            "https://www.konilai.space",
            "https://elasweb.vercel.app",
            "http://localhost:3000",
            ...configured,
        ])
    )
}

function getTokenFromSocket(socket) {
    const authToken = socket.handshake.auth?.token
    if (authToken) return authToken

    const header = socket.handshake.headers?.authorization
    if (header && header.startsWith("Bearer ")) {
        return header.slice(7)
    }

    return null
}

function normalizeRoom(room, id) {
    if (!room || !id) return null

    if (room === "group") return `group:${id}`
    if (room === "session") return `session:${id}`
    if (room === "user") return `user:${id}`

    return String(id)
}

async function canJoinRoom(user, room, id) {
    if (user.role === "ADMIN") return true

    if (room === "user") {
        return id === user.id
    }

    if (room === "group") {
        const group = await prisma.group.findUnique({
            where: { id },
        })

        if (!group) return false

        if (user.role === "TEACHER" && group.teacherId === user.id) {
            return true
        }

        const member = await prisma.groupMember.findUnique({
            where: {
                groupId_userId: {
                    groupId: id,
                    userId: user.id,
                },
            },
        })

        return !!member
    }

    if (room === "session") {
        const session = await prisma.session.findUnique({
            where: { id },
            include: { group: true },
        })

        if (!session) return false

        if (user.role === "TEACHER" && session.createdById === user.id) {
            return true
        }

        const member = await prisma.groupMember.findUnique({
            where: {
                groupId_userId: {
                    groupId: session.groupId,
                    userId: user.id,
                },
            },
        })

        return !!member
    }

    return false
}

export function initSocket(server) {
    io = new Server(server, {
        cors: {
            origin: getAllowedOrigins(),
            credentials: true,
        },
    })

    io.use(async (socket, next) => {
        try {
            const token = getTokenFromSocket(socket)

            if (!token) {
                return next(new Error("Unauthorized"))
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET)

            const userId = decoded.id || decoded.sub || decoded.userId

            if (!userId) {
                return next(new Error("Invalid token"))
            }

            const user = await prisma.user.findUnique({
                where: { id: userId },
                select: {
                    id: true,
                    role: true,
                    email: true,
                    firstName: true,
                    lastName: true,
                },
            })

            if (!user) {
                return next(new Error("User not found"))
            }

            socket.user = user

            return next()
        } catch (e) {
            return next(new Error("Unauthorized"))
        }
    })

    io.on("connection", (socket) => {
        const user = socket.user

        console.log("[Socket.IO] connected", socket.id, user.id, user.role)

        socket.join(`user:${user.id}`)

        socket.emit("socket:ready", {
            socketId: socket.id,
            userId: user.id,
            role: user.role,
        })

        socket.on("joinRoom", async (roomId, callback) => {
            try {
                if (!roomId) {
                    callback?.({ ok: false, error: "roomId required" })
                    return
                }

                socket.join(String(roomId))

                callback?.({ ok: true, roomId })
            } catch {
                callback?.({ ok: false, error: "Failed to join room" })
            }
        })

        socket.on("join", async (payload = {}, callback) => {
            try {
                const room = payload.room || payload.scope
                const id = payload.id || payload.groupId || payload.sessionId || user.id

                const roomKey = normalizeRoom(room, id)

                if (!roomKey) {
                    callback?.({ ok: false, error: "room and id required" })
                    return
                }

                const allowed = await canJoinRoom(user, room, id)

                if (!allowed) {
                    callback?.({ ok: false, error: "Forbidden" })
                    return
                }

                socket.join(roomKey)

                callback?.({
                    ok: true,
                    room,
                    id,
                    roomKey,
                })

                socket.emit("joined-room", {
                    room,
                    id,
                    roomKey,
                })
            } catch (e) {
                console.error("[Socket.IO] join error", e)
                callback?.({ ok: false, error: "Join failed" })
            }
        })

        socket.on("subscribe", async (payload = {}, callback) => {
            try {
                let room = payload.scope
                let id = payload.id

                if (payload.scope === "group") {
                    id = payload.groupId || payload.id
                }

                if (payload.scope === "session") {
                    id = payload.sessionId || payload.id
                }

                if (payload.scope === "user") {
                    room = "user"
                    id = user.id
                }

                const roomKey = normalizeRoom(room, id)

                if (!roomKey) {
                    callback?.({ ok: false, error: "scope and id required" })
                    return
                }

                const allowed = await canJoinRoom(user, room, id)

                if (!allowed) {
                    callback?.({ ok: false, error: "Forbidden" })
                    return
                }

                socket.join(roomKey)

                callback?.({
                    ok: true,
                    scope: room,
                    id,
                    roomKey,
                })
            } catch (e) {
                console.error("[Socket.IO] subscribe error", e)
                callback?.({ ok: false, error: "Subscribe failed" })
            }
        })

        socket.on("leave", (payload = {}, callback) => {
            const room = payload.room || payload.scope
            const id = payload.id || payload.groupId || payload.sessionId
            const roomKey = normalizeRoom(room, id)

            if (roomKey) {
                socket.leave(roomKey)
            }

            callback?.({ ok: true })
        })

        socket.on("sendMessage", (data = {}, callback) => {
            const roomId = data.roomId || data.roomKey

            if (!roomId) {
                callback?.({ ok: false, error: "roomId required" })
                return
            }

            io.to(roomId).emit("receiveMessage", data)

            callback?.({ ok: true })
        })

        socket.on("chat-send", (data = {}, callback) => {
            const room = data.room
            const id = data.id || data.groupId || data.sessionId
            const text = typeof data.text === "string" ? data.text.trim() : ""

            const roomKey = normalizeRoom(room, id)

            if (!roomKey || !text) {
                callback?.({ ok: false, error: "room, id and text required" })
                return
            }

            const payload = {
                type: "chat-event",
                room,
                id,
                from: user.id,
                text,
                ts: new Date().toISOString(),
            }

            io.to(roomKey).emit("chat-event", payload)
            io.to(roomKey).emit("realtime:event", payload)

            callback?.({ ok: true, event: payload })
        })

        socket.on("typing", (data = {}) => {
            const roomId = data.roomId || data.roomKey

            if (!roomId) return

            socket.to(roomId).emit("typing", {
                ...data,
                userId: user.id,
            })
        })

        function getSignalRoom(data = {}) {
            return data.roomId || data.roomKey || (data.sessionId ? `session:${data.sessionId}` : null)
        }

        socket.on("video-signal", (data = {}) => {
            const roomId = getSignalRoom(data)

            if (!roomId) return

            socket.to(roomId).emit("video-signal", {
                ...data,
                from: socket.id,
                userId: user.id,
            })
        })

        socket.on("webrtc-offer", (data = {}) => {
            const roomId = getSignalRoom(data)

            if (!roomId) return

            socket.to(roomId).emit("webrtc-offer", {
                ...data,
                from: socket.id,
                userId: user.id,
            })
        })

        socket.on("webrtc-answer", (data = {}) => {
            const roomId = getSignalRoom(data)

            if (!roomId) return

            socket.to(roomId).emit("webrtc-answer", {
                ...data,
                from: socket.id,
                userId: user.id,
            })
        })

        socket.on("webrtc-ice", (data = {}) => {
            const roomId = getSignalRoom(data)

            if (!roomId) return

            socket.to(roomId).emit("webrtc-ice", {
                ...data,
                from: socket.id,
                userId: user.id,
            })
        })

        socket.on("disconnect", () => {
            console.log("[Socket.IO] disconnected", socket.id)
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

export function emitRealtime(roomKey, payload) {
    const socket = getIO()

    socket.to(roomKey).emit("realtime:event", payload)

    if (payload?.type) {
        socket.to(roomKey).emit(payload.type, payload)
    }
}

export function broadcastSessionChatMessage(sessionId, payload) {
    const socket = getIO()
    const roomKey = `session:${sessionId}`

    socket.to(roomKey).emit("chat-event", payload)
    socket.to(roomKey).emit("realtime:event", payload)

    if (payload?.type) {
        socket.to(roomKey).emit(payload.type, payload)
    }
}

export function broadcastSessionEvent(sessionId, payload) {
    emitRealtime(`session:${sessionId}`, payload)
}

export function broadcastGroupEvent(groupId, payload) {
    emitRealtime(`group:${groupId}`, payload)
}

export function broadcastUserEvent(userId, payload) {
    emitRealtime(`user:${userId}`, payload)
}