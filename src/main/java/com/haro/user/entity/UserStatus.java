package com.haro.user.entity;

/**
 * Account lifecycle states, stored as strings in {@code users.status}.
 */
public final class UserStatus {
    /** Registered, email not yet verified. Can log in, but the JWT carries {@code email_verified=false}. */
    public static final String PENDING_VERIFICATION = "PENDING_VERIFICATION";
    public static final String ACTIVE = "ACTIVE";
    /** Blocked by an admin: cannot log in or refresh. */
    public static final String SUSPENDED = "SUSPENDED";
    /** Self-deleted and anonymized (FR-ACC-04). The row is kept because other services reference the id. */
    public static final String DELETED = "DELETED";

    private UserStatus() {
    }
}
