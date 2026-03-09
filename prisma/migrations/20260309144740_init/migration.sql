-- AlterTable
ALTER TABLE "User" ADD COLUMN     "inviteCode" TEXT,
ADD COLUMN     "organization" TEXT,
ADD COLUMN     "profileUrl" TEXT,
ALTER COLUMN "status" SET DEFAULT 'APPROVED';
