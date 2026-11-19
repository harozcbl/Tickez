package com.haro.user.controller;

import com.haro.user.dto.*;
import com.haro.user.service.AuthService;
import com.haro.user.service.EmailVerificationService;
import com.haro.user.service.PasswordResetService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    static final String PASSWORD_RESET_MESSAGE =
            "If an account exists for this email, a password reset link has been sent";
    static final String RESEND_VERIFICATION_MESSAGE =
            "If this email belongs to an unverified account, a verification email has been sent";
    static final String EMAIL_VERIFIED_MESSAGE = "Email verified successfully";

    private final AuthService authService;
    private final PasswordResetService passwordResetService;
    private final EmailVerificationService emailVerificationService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal UUID userId,
                                       @Valid @RequestBody LogoutRequest logoutRequest) {
        authService.logout(userId, logoutRequest.sessionId());
        return ResponseEntity.noContent().build();
    }

    /** The reset token is delivered by email only; the response is identical whether or not the email exists. */
    @PostMapping("/password-reset")
    public ResponseEntity<Map<String, String>> requestPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        passwordResetService.requestReset(request);
        return ResponseEntity.accepted().body(Map.of("message", PASSWORD_RESET_MESSAGE));
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<Void> confirmPasswordReset(@Valid @RequestBody PasswordResetConfirmRequest request) {
        passwordResetService.resetPassword(request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        emailVerificationService.verifyEmail(request);
        return ResponseEntity.ok(Map.of("message", EMAIL_VERIFIED_MESSAGE));
    }

    /** Link target used in the verification email. */
    @GetMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam UUID tokenId, @RequestParam String token) {
        emailVerificationService.verifyEmail(tokenId, token);
        return ResponseEntity.ok(Map.of("message", EMAIL_VERIFIED_MESSAGE));
    }

    /** The token is delivered by email only; the response is identical whether or not the email exists. */
    @PostMapping("/resend-verification")
    public ResponseEntity<Map<String, String>> resendVerification(
            @Valid @RequestBody ResendVerificationRequest request
    ) {
        emailVerificationService.resendVerification(request);
        return ResponseEntity.accepted().body(Map.of("message", RESEND_VERIFICATION_MESSAGE));
    }
}
