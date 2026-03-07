import prisma from "./prisma.js"

export async function createAuditLog({
                                         actorId,
                                         action,
                                         entityType,
                                         entityId = null,
                                         meta = null,
                                     }) {
    try {
        const metaString =
            meta == null
                ? null
                : typeof meta === "string"
                    ? meta
                    : JSON.stringify(meta)

        await prisma.auditLog.create({
            data: {
                actorId,
                action,
                entityType,
                entityId,
                meta: metaString,
            },
        })
    } catch (err) {
        console.error("AUDIT ERROR:", err)
    }
}

/**
 * Shortcut for routes
 */
export async function logAudit(actorId, action, entityType, entityId, meta) {
    return createAuditLog({ actorId, action, entityType, entityId, meta })
}