package com.haro.user.dto;

import jakarta.validation.constraints.NotBlank;

/** Password re-entry required to delete the account. */
public record DeleteAccountRequest(@NotBlank String password) {
}
