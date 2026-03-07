-- CreateIndex (inviteeEmail for faster lookups)
CREATE INDEX "Invitation_inviteeEmail_idx" ON "Invitation"("inviteeEmail");

-- CreateIndex (unique: one invitation per group+email, prevents duplicates)
CREATE UNIQUE INDEX "Invitation_groupId_inviteeEmail_key" ON "Invitation"("groupId", "inviteeEmail");
