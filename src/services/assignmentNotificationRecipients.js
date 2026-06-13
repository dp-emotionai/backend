const DISABLED_USER_STATUSES = new Set([
    "pending",
    "blocked",
]);

const normalizeLower = (value) =>
    String(value || "")
        .trim()
        .toLowerCase();

/**
 * Account access in authMiddleware is allowed for APPROVED and LIMITED users.
 * Keep assignment notification eligibility aligned with the same rule:
 * PENDING and BLOCKED users are excluded, LIMITED students are eligible.
 */
export function isEligibleAssignmentRecipient(member) {
    const memberRole = normalizeLower(member?.role);
    const memberStatus = normalizeLower(
        member?.status
    );
    const userRole = normalizeLower(
        member?.user?.role
    );
    const userStatus = normalizeLower(
        member?.user?.status
    );

    return Boolean(
        member?.user &&
        memberRole === "student" &&
        memberStatus === "active" &&
        userRole === "student" &&
        !DISABLED_USER_STATUSES.has(
            userStatus
        ) &&
        member.user.notificationSettings
            ?.assignmentNotifications !== false
    );
}

export function logGroupMembers(
    groupId,
    members
) {
    console.log("GROUP MEMBERS FOUND", {
        groupId,
        count: members.length,
        members: members.map((member) => ({
            memberId: member.id,
            userId: member.user?.id,
            email: member.user?.email,
            userRole: member.user?.role,
            userStatus: member.user?.status,
            memberRole: member.role,
            memberStatus: member.status,
            removedAt: member.removedAt,
        })),
    });
}

export function logNotificationRecipients(
    groupId,
    recipients
) {
    console.log("NOTIFICATION RECIPIENTS", {
        groupId,
        count: recipients.length,
        userIds: recipients.map(
            (item) => item.user.id
        ),
    });
}

export function matchesAssignmentNotification(
    data,
    { taskId, testId = null }
) {
    if (!data || typeof data !== "object") {
        return false;
    }

    if (
        testId &&
        String(data.testId || "") ===
        String(testId)
    ) {
        return true;
    }

    return (
        String(data.taskId || "") ===
        String(taskId)
    );
}
