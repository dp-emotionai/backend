/**
 * One-time script: normalize all existing user emails to lowercase and trimmed.
 * Run if you use `prisma db push` and do not run migrations (e.g. on Render).
 *
 * Usage: node scripts/normalize-user-emails.js
 * Requires: DATABASE_URL in .env (or run from project root so dotenv loads).
 */

import prisma from "../src/utils/prisma.js";

async function main() {
    const result = await prisma.$executeRawUnsafe(`
      UPDATE "User"
      SET email = LOWER(TRIM(email))
      WHERE email != LOWER(TRIM(email))
    `);
    console.log("Normalized user emails. Rows updated:", result);
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(() => prisma.$disconnect());
