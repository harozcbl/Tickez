package com.haro.user.event;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Published on {@code user.events} when a user deletes their account, so other services can purge personal data
 * they hold for this user (FR-ACC-04).
 */
public record UserDeletedEvent(
        String type,
        UUID userId,
        OffsetDateTime deletedAt
) {
    public static final String TYPE = "USER_DELETED";

    public UserDeletedEvent(UUID userId, OffsetDateTime deletedAt) {
        this(TYPE, userId, deletedAt);
    }
}
