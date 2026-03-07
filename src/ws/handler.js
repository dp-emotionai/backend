import jwt from "jsonwebtoken"
import prisma from "../utils/prisma.js"

import {
    createClient,
    addClientToRoom,
    removeClientFromAllRooms,
    broadcastToRoom
} from "./rooms.js"

function send(socket, msg) {
    if (socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(msg))
    }
}

function roomName(type, id) {
    return type === "group"
        ? `group_${id}`
        : `session_${id}`
}

export async function handleMessage(socket, clientRef, raw) {
    let msg

    try {
        msg = JSON.parse(raw)
    } catch {
        send(socket, { type: "error", message: "Invalid JSON" })
        return
    }

    if (msg.type === "ping") {
        send(socket, { type: "pong" })
        return
    }

    if (msg.type === "auth") {
        try {
            const decoded = jwt.verify(
                msg.token,
                process.env.JWT_SECRET
            )

            const user = await prisma.user.findUnique({
                where: { id: decoded.id }
            })

            if (!user) {
                send(socket, { type: "error", message: "User not found" })
                socket.close()
                return
            }

            const client = createClient(
                socket,
                user.id,
                user.role
            )

            clientRef.current = client

            send(socket, {
                type: "ready",
                userId: user.id,
                role: user.role
            })
        } catch {
            send(socket, { type: "error", message: "Invalid token" })
            socket.close()
        }

        return
    }

    const client = clientRef.current

    if (!client) {
        send(socket, {
            type: "error",
            message: "Authenticate first"
        })
        return
    }

    if (msg.type === "join") {
        const room = roomName(msg.room, msg.id)

        addClientToRoom(client, room)

        send(socket, {
            type: "joined-room",
            room
        })

        return
    }

    if (msg.type === "leave") {
        removeClientFromAllRooms(client)

        send(socket, { type: "left-room" })

        return
    }
}

export function handleDisconnect(clientRef) {
    const client = clientRef.current

    if (!client) return

    removeClientFromAllRooms(client)

    clientRef.current = null
}

export function broadcastChatEvent(room, event) {
    broadcastToRoom(room, {
        type: "chat-event",
        room,
        event
    })
}