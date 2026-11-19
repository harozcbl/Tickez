package com.haro.user.service;

import com.haro.common.web.BadRequestException;
import com.haro.user.dto.PasswordResetConfirmRequest;
import com.haro.user.dto.PasswordResetRequest;
import com.haro.user.entity.PasswordResetToken;
import com.haro.user.entity.User;
import com.haro.user.entity.UserStatus;
import com.haro.user.event.EmailNotificationEvent;
import com.haro.user.repository.PasswordResetTokenRepository;
import com.haro.user.repository.SessionRepository;
import com.haro.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private PasswordResetTokenRepository tokenRepository;
    @Mock
    private SessionRepository sessionRepository;
    @Mock
    private OutboxService outboxService;

    @InjectMocks
    private PasswordResetService passwordResetService;

    @Test
    void requestResetEmailsTokenAndInvalidatesOlderOnes() {
        User user = User.builder().id(UUID.randomUUID()).email("user@test.com").name("User")
                .status(UserStatus.ACTIVE).build();
        UUID tokenId = UUID.randomUUID();
        when(userRepository.findByEmailIgnoreCase("user@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode(anyString())).thenReturn("hash");
        when(tokenRepository.save(any(PasswordResetToken.class))).thenAnswer(inv -> {
            PasswordResetToken t = inv.getArgument(0);
            t.setId(tokenId);
            return t;
        });

        passwordResetService.requestReset(new PasswordResetRequest("user@test.com"));

        verify(tokenRepository).invalidateUnusedTokens(eq(user), any());
        ArgumentCaptor<EmailNotificationEvent> event = ArgumentCaptor.forClass(EmailNotificationEvent.class);
        verify(outboxService).saveEvent(event.capture());
        assertEquals(PasswordResetService.EVENT_TYPE, event.getValue().type());
        assertEquals(tokenId.toString(), event.getValue().payload().get("tokenId"));
        assertNotNull(event.getValue().payload().get("rawToken"));
    }

    @Test
    void requestResetIsSilentForUnknownEmail() {
        when(userRepository.findByEmailIgnoreCase("nobody@test.com")).thenReturn(Optional.empty());

        assertDoesNotThrow(() -> passwordResetService.requestReset(new PasswordResetRequest("nobody@test.com")));

        verifyNoInteractions(tokenRepository, outboxService);
    }

    @Test
    void resetPasswordUpdatesHashMarksTokenUsedAndRevokesSessions() {
        User user = User.builder().id(UUID.randomUUID()).passwordHash("old").build();
        PasswordResetToken token = PasswordResetToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash("token-hash")
                .expiresAt(OffsetDateTime.now().plusMinutes(5))
                .build();
        when(tokenRepository.findById(token.getId())).thenReturn(Optional.of(token));
        when(passwordEncoder.matches("raw", "token-hash")).thenReturn(true);
        when(passwordEncoder.encode("newPassword123")).thenReturn("new-hash");

        passwordResetService.resetPassword(new PasswordResetConfirmRequest(token.getId(), "raw", "newPassword123"));

        assertEquals("new-hash", user.getPasswordHash());
        assertNotNull(token.getUsedAt());
        verify(sessionRepository).deleteAllByUser(user);
    }

    @Test
    void resetPasswordRejectsUsedToken() {
        PasswordResetToken token = PasswordResetToken.builder()
                .id(UUID.randomUUID())
                .usedAt(OffsetDateTime.now())
                .expiresAt(OffsetDateTime.now().plusMinutes(5))
                .build();
        when(tokenRepository.findById(token.getId())).thenReturn(Optional.of(token));

        assertThrows(BadRequestException.class, () -> passwordResetService.resetPassword(
                new PasswordResetConfirmRequest(token.getId(), "raw", "newPassword123")));

        verifyNoInteractions(sessionRepository);
    }
}
