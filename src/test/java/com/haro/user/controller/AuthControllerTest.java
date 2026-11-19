package com.haro.user.controller;

import com.haro.user.dto.*;
import com.haro.user.service.AuthService;
import com.haro.user.service.EmailVerificationService;
import com.haro.user.service.PasswordResetService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;
    @Mock
    private PasswordResetService passwordResetService;
    @Mock
    private EmailVerificationService emailVerificationService;

    @InjectMocks
    private AuthController authController;

    @Test
    void loginReturnsOkAndAuthResponse() {
        LoginRequest request = new LoginRequest("user@test.com", "secret123");
        AuthResponse expected = new AuthResponse(
                "access-token",
                "refresh-token",
                UUID.randomUUID(),
                new UserResponse(UUID.randomUUID(), "user@test.com", "User", null, null, "ACTIVE", null, null, null, Set.of("ROLE_FAN"))
        );
        when(authService.login(request)).thenReturn(expected);

        ResponseEntity<AuthResponse> response = authController.login(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(expected, response.getBody());
        verify(authService).login(request);
    }

    @Test
    void refreshReturnsOkAndAuthResponse() {
        RefreshTokenRequest request = new RefreshTokenRequest(UUID.randomUUID(), "refresh-token");
        AuthResponse expected = new AuthResponse("new-access", "new-refresh", UUID.randomUUID(), null);
        when(authService.refresh(request)).thenReturn(expected);

        ResponseEntity<AuthResponse> response = authController.refresh(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(expected, response.getBody());
        verify(authService).refresh(request);
    }

    @Test
    void logoutDeletesCallersSessionAndReturnsNoContent() {
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();

        ResponseEntity<Void> response = authController.logout(userId, new LogoutRequest(sessionId));

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        assertNull(response.getBody());
        verify(authService).logout(userId, sessionId);
    }

    @Test
    void passwordResetReturnsAcceptedWithoutToken() {
        PasswordResetRequest request = new PasswordResetRequest("user@test.com");

        ResponseEntity<Map<String, String>> response = authController.requestPasswordReset(request);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertEquals(Map.of("message", AuthController.PASSWORD_RESET_MESSAGE), response.getBody());
        verify(passwordResetService).requestReset(request);
    }

    @Test
    void confirmPasswordResetReturnsNoContent() {
        PasswordResetConfirmRequest request = new PasswordResetConfirmRequest(UUID.randomUUID(), "token", "newPassword123");

        ResponseEntity<Void> response = authController.confirmPasswordReset(request);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(passwordResetService).resetPassword(request);
    }

    @Test
    void verifyEmailViaBodyReturnsSuccessMessage() {
        VerifyEmailRequest request = new VerifyEmailRequest(UUID.randomUUID(), "token");

        ResponseEntity<Map<String, String>> response = authController.verifyEmail(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Email verified successfully", response.getBody().get("message"));
        verify(emailVerificationService).verifyEmail(request);
    }

    @Test
    void verifyEmailViaQueryReturnsSuccessMessage() {
        UUID tokenId = UUID.randomUUID();
        String token = "raw-token";

        ResponseEntity<Map<String, String>> response = authController.verifyEmail(tokenId, token);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Email verified successfully", response.getBody().get("message"));
        verify(emailVerificationService).verifyEmail(tokenId, token);
    }

    @Test
    void resendVerificationReturnsAcceptedWithoutToken() {
        ResendVerificationRequest request = new ResendVerificationRequest("user@test.com");

        ResponseEntity<Map<String, String>> response = authController.resendVerification(request);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertEquals(Map.of("message", AuthController.RESEND_VERIFICATION_MESSAGE), response.getBody());
        verify(emailVerificationService).resendVerification(request);
    }
}
