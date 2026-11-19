package com.haro.user.service;

import com.haro.common.web.BadRequestException;
import com.haro.common.web.NotFoundException;
import com.haro.user.dto.PasswordResetConfirmRequest;
import com.haro.user.dto.PasswordResetRequest;
import com.haro.user.entity.PasswordResetToken;
import com.haro.user.entity.User;
import com.haro.user.entity.UserStatus;
import com.haro.user.event.EmailNotificationEvent;
import com.haro.user.repository.PasswordResetTokenRepository;
import com.haro.user.repository.SessionRepository;
import com.haro.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetService {
    public static final String EVENT_TYPE = "PASSWORD_RESET";
    private static final int RESET_TOKEN_MINUTES = 10;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final SessionRepository sessionRepository;
    private final OutboxService outboxService;

    /**
     * Emails a reset link if the account exists. Always completes silently so the endpoint cannot be used to
     * discover registered emails. Any earlier unused token is invalidated.
     */
    @Transactional
    public void requestReset(PasswordResetRequest request) {
        userRepository.findByEmailIgnoreCase(request.email())
                .filter(u -> !UserStatus.DELETED.equals(u.getStatus()))
                .ifPresent(this::issueToken);
    }

    @Transactional
    public void resetPassword(PasswordResetConfirmRequest request) {
        PasswordResetToken token = passwordResetTokenRepository.findById(request.tokenId())
                .orElseThrow(() -> new NotFoundException("Invalid reset token"));

        if (token.getUsedAt() != null) {
            throw new BadRequestException("Token has already been used");
        }

        if (token.getExpiresAt().isBefore(OffsetDateTime.now())) {
            throw new BadRequestException("Expired reset token");
        }

        if (!passwordEncoder.matches(request.token(), token.getTokenHash())) {
            throw new BadRequestException("Invalid reset token");
        }

        User user = token.getUser();
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        token.setUsedAt(OffsetDateTime.now());
        passwordResetTokenRepository.save(token);

        // Log out everywhere: whoever knew the old password must not keep a valid refresh token.
        sessionRepository.deleteAllByUser(user);
    }

    private void issueToken(User user) {
        OffsetDateTime now = OffsetDateTime.now();
        passwordResetTokenRepository.invalidateUnusedTokens(user, now);

        String rawToken = UUID.randomUUID().toString();
        PasswordResetToken token = passwordResetTokenRepository.save(PasswordResetToken.builder()
                .user(user)
                .tokenHash(passwordEncoder.encode(rawToken))
                .expiresAt(now.plusMinutes(RESET_TOKEN_MINUTES))
                .build());

        outboxService.saveEvent(new EmailNotificationEvent(
                EVENT_TYPE,
                user.getId(),
                user.getEmail(),
                user.getName(),
                Map.of("tokenId", token.getId().toString(), "rawToken", rawToken)
        ));
    }
}
