package com.haro.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Admin request to suspend or re-activate an account. {@code ACTIVE} restores the account to
 * {@code ACTIVE} or {@code PENDING_VERIFICATION}, depending on whether the email is verified.
 */
public record UpdateUserStatusRequest(
        @NotBlank @Pattern(regexp = "ACTIVE|SUSPENDED", message = "must be ACTIVE or SUSPENDED") String status,
        @Size(max = 500) String reason
) {
}
