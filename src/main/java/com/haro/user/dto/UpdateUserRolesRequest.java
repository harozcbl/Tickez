package com.haro.user.dto;

import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

/** Admin request replacing a user's full role set, e.g. {@code ["ROLE_FAN", "ROLE_ORGANIZER"]}. */
public record UpdateUserRolesRequest(@NotEmpty Set<String> roles) {
}
