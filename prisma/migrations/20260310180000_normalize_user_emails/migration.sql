-- One-time data migration: normalize existing user emails to lowercase and trimmed.
-- Ensures login with email.trim().toLowerCase() finds all users.
-- If you have duplicate emails that differ only by case (e.g. User@Mail.com and user@mail.com),
-- resolve duplicates manually before running this migration.

UPDATE "User"
SET email = LOWER(TRIM(email))
WHERE email != LOWER(TRIM(email));
