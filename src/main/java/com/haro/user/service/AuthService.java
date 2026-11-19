package com.haro.user.service;

import com.haro.common.web.BadRequestException;
import com.haro.common.web.NotFoundException;
import com.haro.user.config.JwtProperties;
import com.haro.user.dto.AuthResponse;
import com.haro.user.dto.LoginRequest;
import com.haro.user.dto.RefreshTokenRequest;
import com.haro.user.entity.Session;
import com.haro.user.entity.User;
import com.haro.user.entity.UserStatus;
import com.haro.user.repository.SessionRepository;
import com.haro.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {
    static final String INVALID_CREDENTIALS = "Invalid email or password";
    static final String ACCOUNT_SUSPENDED = "Account is suspended";

    private final UserService userService;
    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    /**
     * Unknown email and wrong password produce the same error so the endpoint cannot be used to probe accounts.
     * Accounts pending email verification may log in; their token carries {@code email_verified=false}.
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmailIgnoreCase(request.email())
                .filter(u -> u.getPasswordHash() != null)
                .filter(u -> passwordEncoder.matches(request.password(), u.getPasswordHash()))
                .orElseThrow(() -> new BadRequestException(INVALID_CREDENTIALS));

        ensureCanAuthenticate(user);
        return createSession(user, userService.loadRoles(user));
    }

    // noRollbackFor: the session deletions below must survive the exception that follows them.
    @Transactional(noRollbackFor = BadRequestException.class)
    public AuthResponse refresh(RefreshTokenRequest request) {
        Session session = sessionRepository.findById(request.sessionId())
                .orElseThrow(() -> new NotFoundException("Session not found"));

        if (session.getExpiresAt().isBefore(OffsetDateTime.now())) {
            sessionRepository.delete(session);
            throw new BadRequestException("Refresh token expired");
        }

        if (!passwordEncoder.matches(request.refreshToken(), session.getRefreshTokenHash())) {
            sessionRepository.delete(session);
            throw new BadRequestException("Invalid refresh token");
        }

        User user = session.getUser();
        if (!canAuthenticate(user)) {
            sessionRepository.delete(session);
            ensureCanAuthenticate(user);
        }

        String newRefreshToken = UUID.randomUUID().toString();
        session.setRefreshTokenHash(passwordEncoder.encode(newRefreshToken));
        session.setExpiresAt(refreshExpiresAt());
        sessionRepository.save(session);

        Set<String> roles = userService.loadRoles(user);
        return new AuthResponse(
                generateAccessToken(user, roles),
                newRefreshToken,
                session.getId(),
                userService.toResponse(user, roles)
        );
    }

    /** Deletes the session only if it belongs to the caller; other sessions are silently ignored. */
    @Transactional
    public void logout(UUID userId, UUID sessionId) {
        sessionRepository.deleteByIdAndUserId(sessionId, userId);
    }

    private boolean canAuthenticate(User user) {
        return !UserStatus.SUSPENDED.equals(user.getStatus()) && !UserStatus.DELETED.equals(user.getStatus());
    }

    private void ensureCanAuthenticate(User user) {
        if (UserStatus.SUSPENDED.equals(user.getStatus())) {
            throw new BadRequestException(ACCOUNT_SUSPENDED);
        }
        if (UserStatus.DELETED.equals(user.getStatus())) {
            throw new BadRequestException(INVALID_CREDENTIALS);
        }
    }

    private String generateAccessToken(User user, Set<String> roles) {
        return jwtService.generateAccessToken(user.getId(), user.getEmail(), roles, user.getEmailVerifiedAt() != null);
    }

    private OffsetDateTime refreshExpiresAt() {
        long refreshMs = jwtProperties.refreshTokenExpirationMs();
        return OffsetDateTime.now().plus(refreshMs, ChronoUnit.MILLIS);
    }

    private AuthResponse createSession(User user, Set<String> roles) {
        String refreshToken = UUID.randomUUID().toString();

        Session session = Session.builder()
                .user(user)
                .refreshTokenHash(passwordEncoder.encode(refreshToken))
                .expiresAt(refreshExpiresAt())
                .build();
        session = sessionRepository.save(session);

        return new AuthResponse(
                generateAccessToken(user, roles),
                refreshToken,
                session.getId(),
                userService.toResponse(user, roles)
        );
    }
}
