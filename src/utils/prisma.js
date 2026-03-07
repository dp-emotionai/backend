import { PrismaClient } from "@prisma/client"

/**
 * Single PrismaClient instance (singleton).
 * For production under high load, add connection pooling to DATABASE_URL:
 *   postgresql://user:pass@host/db?connection_limit=20
 * This limits concurrent connections and prevents the DB from being overwhelmed.
 * @see https://www.prisma.io/docs/guides/performance-and-optimization/connection-management
 */
const prisma = new PrismaClient()

export default prisma