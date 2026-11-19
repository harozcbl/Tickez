package com.haro.user.controller;

import com.haro.user.dto.ChangePasswordRequest;
import com.haro.user.dto.DeleteAccountRequest;
import com.haro.user.dto.UpdateProfileRequest;
import com.haro.user.dto.UserRegistrationRequest;
import com.haro.user.dto.UserResponse;
import com.haro.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Self-service account endpoints. The user is always taken from the access token, never from the URL, so a user
 * can only read or change their own account. Admin access to other accounts lives in {@link AdminUserController}.
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<UserResponse> register(@Valid @RequestBody UserRegistrationRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.registerUser(request));
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(@AuthenticationPrincipal UUID userId) {
        return ResponseEntity.ok(userService.getUser(userId));
    }

    @PutMapping("/me")
    public ResponseEntity<UserResponse> updateProfile(
            @AuthenticationPrincipal UUID userId,
            @Valid @RequestBody UpdateProfileRequest request
    ) {
        return ResponseEntity.ok(userService.updateProfile(userId, request));
    }

    /** Changes the password and logs out all sessions. */
    @PostMapping("/me/password")
    public ResponseEntity<Void> changePassword(
            @AuthenticationPrincipal UUID userId,
            @Valid @RequestBody ChangePasswordRequest request
    ) {
        userService.changePassword(userId, request);
        return ResponseEntity.noContent().build();
    }

    /** Deletes the account and anonymizes personal data (FR-ACC-04). */
    @DeleteMapping("/me")
    public ResponseEntity<Void> deleteAccount(
            @AuthenticationPrincipal UUID userId,
            @Valid @RequestBody DeleteAccountRequest request
    ) {
        userService.deleteAccount(userId, request);
        return ResponseEntity.noContent().build();
    }
}
