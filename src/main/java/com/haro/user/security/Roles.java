package com.haro.user.security;

import java.util.Set;

/**
 * Platform roles (requirements section 2). Stored in {@code user_roles.role} and emitted in the JWT {@code roles} claim.
 */
public final class Roles {
    public static final String FAN = "ROLE_FAN";
    public static final String ORGANIZER = "ROLE_ORGANIZER";
    public static final String GATE_STAFF = "ROLE_GATE_STAFF";
    public static final String SUPPORT = "ROLE_SUPPORT";
    public static final String ADMIN = "ROLE_ADMIN";

    public static final Set<String> ALL = Set.of(FAN, ORGANIZER, GATE_STAFF, SUPPORT, ADMIN);

    private Roles() {
    }
}
