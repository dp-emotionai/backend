import { WebSocketServer } from "ws"
import crypto from "crypto"
import jwt from "jsonwebtoken"
import prisma from "../utils/prisma.js"

const signalingClients = new Map()
const signalingSessions = new Map()

const chatClients = new Map()
const chatRooms = new Map()

const safeJsonParse = (data) => {
    try {
        return JSON.parse(data)
    } catch {
        return null
    }
}

const send = (ws, payload) => {
    if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify(payload))
    }
}

const generateClientId = () => {
    if (typeof crypto.randomUUID === "function") {
        return crypto.randomUUID()
    }
    return crypto.randomBytes(16).toString("hex")
}

export function broadcastSessionChatMessage(sessionId, payload) {
    const roomKey = `session:${sessionId}`
    const members = chatRooms.get(roomKey)
    if (!members || members.size === 0) return

    for (const member of members) {
        send(member, payload)
    }
}

function handleSignalingConnection(ws) {
    let clientInfo = null

    ws.on("message", (raw) => {
        const msg = safeJsonParse(raw)
        if (!msg || typeof msg.type !== "string") {
            send(ws, { type: "error", message: "Invalid message" })
            return
        }

        if (msg.type === "join") {
            const sessionId = typeof msg.sessionId === "string" ? msg.sessionId : null
            const role = msg.role === "teacher" || msg.role === "student" ? msg.role : "student"

            if (!sessionId) {
                send(ws, { type: "error", message: "sessionId required" })
                return
            }

            const clientId = generateClientId()
            clientInfo = { id: clientId, sessionId, role }
            signalingClients.set(ws, clientInfo)

            let sessionMap = signalingSessions.get(sessionId)
            if (!sessionMap) {
                sessionMap = new Map()
                signalingSessions.set(sessionId, sessionMap)
            }

            const participants = Array.from(sessionMap.values()).map((c) => ({
                id: c.id,
                role: c.role,
                sessionId: c.sessionId,
            }))

            sessionMap.set(clientId, { ws, id: clientId, role, sessionId })

            console.log("[WS signaling] join", { sessionId, role, clientId })

            send(ws, {
                type: "joined",
                self: { id: clientId, role, sessionId },
                participants,
            })

            for (const [otherId, otherClient] of sessionMap.entries()) {
                if (otherId === clientId) continue
                send(otherClient.ws, {
                    type: "user-joined",
                    participant: { id: clientId, role, sessionId },
                })
            }

            return
        }

        if (!clientInfo) {
            send(ws, { type: "error", message: "Join first" })
            return
        }

        const { id: fromId, sessionId } = clientInfo
        const sessionMap = signalingSessions.get(sessionId)
        if (!sessionMap) {
            send(ws, { type: "error", message: "Session not joined" })
            return
        }

        if (msg.type === "leave") {
            cleanupSignalingClient(ws, clientInfo)
            return
        }

        if (msg.type === "webrtc-offer" || msg.type === "webrtc-answer" || msg.type === "webrtc-ice") {
            const toId = typeof msg.to === "string" ? msg.to : null
            if (!toId) {
                send(ws, { type: "error", message: "Missing 'to' clientId" })
                return
            }
            const target = sessionMap.get(toId)
            if (!target) {
                send(ws, { type: "error", message: "Target client not found" })
                console.error("[WS signaling] target not found", { from: fromId, to: toId })
                return
            }

            const forward = {
                type: msg.type,
                from: fromId,
            }

            if (msg.type === "webrtc-offer" || msg.type === "webrtc-answer") {
                forward.sdp = msg.sdp
            } else if (msg.type === "webrtc-ice") {
                forward.candidate = msg.candidate
            }

            send(target.ws, forward)
            console.log("[WS signaling]", msg.type, { from: fromId, to: toId })
            return
        }

        send(ws, { type: "error", message: "Unknown message type" })
    })

    ws.on("close", () => {
        if (clientInfo) {
            cleanupSignalingClient(ws, clientInfo)
        }
    })
}

function cleanupSignalingClient(ws, clientInfo) {
    signalingClients.delete(ws)
    const { id, sessionId } = clientInfo
    const sessionMap = signalingSessions.get(sessionId)
    if (!sessionMap) return

    sessionMap.delete(id)
    console.log("[WS signaling] leave", { sessionId, clientId: id })
    for (const [, otherClient] of sessionMap.entries()) {
        send(otherClient.ws, {
            type: "user-left",
            participant: { id, sessionId },
        })
    }
    if (sessionMap.size === 0) {
        signalingSessions.delete(sessionId)
    }
}

function handleChatConnection(ws) {
    let client = null

    const leaveAllRooms = () => {
        for (const [roomKey, members] of chatRooms.entries()) {
            if (members.delete(ws) && members.size === 0) {
                chatRooms.delete(roomKey)
            }
        }
    }

    ws.on("message", async (raw) => {
        let msg = safeJsonParse(raw)
        if (!msg || typeof msg.type !== "string") {
            send(ws, { type: "error", message: "Invalid message" })
            return
        }

        if (msg.type === "auth") {
            const token = typeof msg.token === "string" ? msg.token : ""
            if (!token) {
                send(ws, { type: "error", message: "Token required" })
                ws.close()
                return
            }
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET)
                client = {
                    userId: decoded.sub || decoded.id || decoded.userId,
                    role: typeof decoded.role === "string" ? decoded.role.toUpperCase() : null,
                }
                chatClients.set(ws, client)
                send(ws, { type: "auth-ok" })
            } catch {
                send(ws, { type: "error", message: "Invalid token" })
                ws.close()
            }
            return
        }

        if (!client) {
            send(ws, { type: "error", message: "Authenticate first" })
            return
        }

        if (msg.type === "subscribe") {
            if (msg.scope === "session" && typeof msg.sessionId === "string") {
                msg = {
                    type: "join",
                    room: "session",
                    id: msg.sessionId,
                }
            } else if (msg.scope === "group" && typeof msg.groupId === "string") {
                msg = {
                    type: "join",
                    room: "group",
                    id: msg.groupId,
                }
            }
        }

        if (msg.type === "join") {
            const room = msg.room === "group" || msg.room === "session" ? msg.room : null
            const id = typeof msg.id === "string" ? msg.id : null
            if (!room || !id) {
                send(ws, { type: "error", message: "room and id required" })
                return
            }
            try {
                if (room === "group") {
                    const group = await prisma.group.findUnique({ where: { id } })
                    if (!group) {
                        send(ws, { type: "error", message: "Group not found" })
                        return
                    }
                    const isAdmin = client.role === "ADMIN"
                    const isTeacher = client.role === "TEACHER" && group.teacherId === client.userId
                    let isMember = false
                    if (!isAdmin && !isTeacher) {
                        const gm = await prisma.groupMember.findUnique({
                            where: { groupId_userId: { groupId: id, userId: client.userId } },
                        })
                        isMember = !!gm
                    }
                    if (!isAdmin && !isTeacher && !isMember) {
                        send(ws, { type: "error", message: "Forbidden" })
                        return
                    }
                }
                if (room === "session") {
                    const session = await prisma.session.findUnique({
                        where: { id },
                        include: { group: true },
                    })
                    if (!session) {
                        send(ws, { type: "error", message: "Session not found" })
                        return
                    }
                    const isAdmin = client.role === "ADMIN"
                    const isOwner = client.role === "TEACHER" && session.createdById === client.userId
                    let isMember = false
                    if (client.role === "STUDENT") {
                        const gm = await prisma.groupMember.findUnique({
                            where: {
                                groupId_userId: { groupId: session.groupId, userId: client.userId },
                            },
                        })
                        isMember = !!gm
                    }
                    if (!isAdmin && !isOwner && !isMember) {
                        send(ws, { type: "error", message: "Forbidden" })
                        return
                    }
                }
            } catch (e) {
                console.error("[WS chat] join error", e)
                send(ws, { type: "error", message: "Join failed" })
                return
            }
            const roomKey = `${room}:${id}`
            let members = chatRooms.get(roomKey)
            if (!members) {
                members = new Set()
                chatRooms.set(roomKey, members)
            }
            members.add(ws)
            send(ws, { type: "joined-room", room, id })
            return
        }

        if (msg.type === "chat-send") {
            const room = msg.room === "group" || msg.room === "session" ? msg.room : null
            const id = typeof msg.id === "string" ? msg.id : null
            const text = typeof msg.text === "string" ? msg.text : ""
            if (!room || !id || !text.trim()) {
                send(ws, { type: "error", message: "room, id and text required" })
                return
            }
            const roomKey = `${room}:${id}`
            const members = chatRooms.get(roomKey)
            if (!members || !members.has(ws)) {
                send(ws, { type: "error", message: "Not in room" })
                return
            }
            const payload = {
                type: "chat-event",
                room,
                id,
                from: client.userId,
                text,
                ts: new Date().toISOString(),
            }
            for (const member of members) {
                send(member, payload)
            }
            return
        }

        send(ws, { type: "error", message: "Unknown message type" })
    })

    ws.on("close", () => {
        chatClients.delete(ws)
        leaveAllRooms()
    })
}

export function initRawWebSockets(server) {
    const signalingWss = new WebSocketServer({ noServer: true })
    const chatWss = new WebSocketServer({ noServer: true })

    signalingWss.on("connection", (ws) => {
        handleSignalingConnection(ws)
    })

    chatWss.on("connection", (ws) => {
        handleChatConnection(ws)
    })

    server.on("upgrade", (request, socket, head) => {
        try {
            const { pathname } = new URL(request.url, "http://localhost")

            if (pathname === "/api/ws") {
                signalingWss.handleUpgrade(request, socket, head, (ws) => {
                    signalingWss.emit("connection", ws, request)
                })
                return
            }

            if (pathname === "/api/ws-chat" || pathname === "/ws-chat") {
                chatWss.handleUpgrade(request, socket, head, (ws) => {
                    chatWss.emit("connection", ws, request)
                })
            }
        } catch {
            socket.destroy()
        }
    })
}