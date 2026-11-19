package com.haro.user.service;

import com.haro.common.web.BadRequestException;
import com.haro.common.web.ConflictException;
import com.haro.common.web.NotFoundException;
import com.haro.user.dto.ResendVerificationRequest;
import com.haro.user.dto.VerifyEmailRequest;
import com.haro.user.entity.EmailVerificationToken;
import com.haro.user.entity.User;
import com.haro.user.entity.UserStatus;
import com.haro.user.event.EmailNotificationEvent;
import com.haro.user.repository.EmailVerificationTokenRepository;
import com.haro.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Email verification is the "verified account" gate required before buying tickets (BR-08; email is used in place
 * of phone verification for now).
 */
@Service
@RequiredArgsConstructor
public class EmailVerificationService {
    private static final Logger log = LoggerFactory.getLogger(EmailVerificationService.class);
    public static final String EVENT_TYPE = "EMAIL_VERIFICATION";
    private static final int TOKEN_EXPIRATION_HOURS = 24;
    private static final int RESEND_COOLDOWN_SECONDS = 60;

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OutboxService outboxService;

    /** Creates a token and queues the verification email. The raw token only leaves the service via that email. */
    @Transactional
    public EmailVerificationResult createVerificationToken(User user) {
        String rawToken = UUID.randomUUID().toString();

        EmailVerificationToken token = EmailVerificationToken.builder()
                .user(user)
                .tokenHash(passwordEncoder.encode(rawToken))
                .expiresAt(OffsetDateTime.now().plusHours(TOKEN_EXPIRATION_HOURS))
                .build();
        token = tokenRepository.save(token);

        outboxService.saveEvent(new EmailNotificationEvent(
                EVENT_TYPE,
                user.getId(),
                user.getEmail(),
                user.getName(),
                Map.of("tokenId", token.getId().toString(), "rawToken", rawToken)
        ));
        return new EmailVerificationResult(token.getId(), rawToken);
    }

    @Transactional
    public void verifyEmail(VerifyEmailRequest request) {
        verifyEmail(request.tokenId(), request.token());
    }

    @Transactional
    public void verifyEmail(UUID tokenId, String rawToken) {
        EmailVerificationToken token = tokenRepository.findById(tokenId)
                .orElseThrow(() -> new NotFoundException("Verification token not found"));

        if (token.getVerifiedAt() != null) {
            throw new ConflictException("Email already verified");
        }

        if (token.getExpiresAt().isBefore(OffsetDateTime.now())) {
            throw new BadRequestException("Verification token expired");
        }

        if (!passwordEncoder.matches(rawToken, token.getTokenHash())) {
            throw new BadRequestException("Invalid verification token");
        }

        OffsetDateTime now = OffsetDateTime.now();
        token.setVerifiedAt(now);
        tokenRepository.save(token);

        User user = token.getUser();
        user.setEmailVerifiedAt(now);
        // Never lift a suspension by verifying an email.
        if (UserStatus.PENDING_VERIFICATION.equals(user.getStatus())) {
            user.setStatus(UserStatus.ACTIVE);
        }
        userRepository.save(user);

        log.info("Email verified for user={}", user.getId());
    }

    /**
     * Sends a new verification email if the account exists, is unverified and the cooldown has passed. Always
     * completes silently so callers cannot learn whether an email is registered.
     */
    @Transactional
    public void resendVerification(ResendVerificationRequest request) {
        User user = userRepository.findByEmailIgnoreCase(request.email()).orElse(null);
        if (user == null || user.getEmailVerifiedAt() != null || UserStatus.DELETED.equals(user.getStatus())) {
            return;
        }

        List<EmailVerificationToken> existingTokens = tokenRepository.findByUserAndVerifiedAtIsNullOrderByCreatedAtDesc(user);
        if (!existingTokens.isEmpty()) {
            OffsetDateTime cooldownEnd = existingTokens.getFirst().getCreatedAt().plusSeconds(RESEND_COOLDOWN_SECONDS);
            if (cooldownEnd.isAfter(OffsetDateTime.now())) {
                log.debug("Verification resend skipped (cooldown) for user={}", user.getId());
                return;
            }
        }

        createVerificationToken(user);
    }

    public record EmailVerificationResult(UUID tokenId, String rawToken) {
    }
}
