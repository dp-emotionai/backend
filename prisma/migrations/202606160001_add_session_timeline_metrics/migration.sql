ALTER TABLE "SessionTimelineBucket" ADD COLUMN "avgFatigue" DOUBLE PRECISION;
ALTER TABLE "SessionTimelineBucket" ADD COLUMN "avgConfidence" DOUBLE PRECISION;
ALTER TABLE "SessionTimelineBucket" ADD COLUMN "dominantEmotion" TEXT;
ALTER TABLE "SessionTimelineBucket" ADD COLUMN "sampleCount" INTEGER NOT NULL DEFAULT 0;