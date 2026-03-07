import { randomUUID } from "crypto"

const rooms = new Map()

export function createClient(socket, userId, role) {
    return {
        id: randomUUID(),
        socket,
        userId,
        role,
        rooms: new Set()
    }
}

export function addClientToRoom(client, room) {
    let set = rooms.get(room)

    if (!set) {
        set = new Set()
        rooms.set(room, set)
    }

    set.add(client)
    client.rooms.add(room)
}

export function removeClientFromRoom(client, room) {
    const set = rooms.get(room)

    if (!set) return

    set.delete(client)

    if (set.size === 0) {
        rooms.delete(room)
    }

    client.rooms.delete(room)
}

export function removeClientFromAllRooms(client) {
    for (const room of client.rooms) {
        removeClientFromRoom(client, room)
    }
}

export function broadcastToRoom(room, message, options = {}) {
    const set = rooms.get(room)

    if (!set) return

    const payload = JSON.stringify(message)

    for (const client of set) {
        if (options.excludeClientId && client.id === options.excludeClientId) {
            continue
        }

        if (client.socket.readyState === client.socket.OPEN) {
            client.socket.send(payload)
        }
    }
}