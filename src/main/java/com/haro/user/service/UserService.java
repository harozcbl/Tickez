package com.haro.user.service;

import com.haro.common.web.BadRequestException;
import com.haro.common.web.ConflictException;
import com.haro.common.web.NotFoundException;
import com.haro.user.dto.ChangePasswordRequest;
import com.haro.user.dto.DeleteAccountRequest;
import com.haro.user.dto.UpdateProfileRequest;
import com.haro.user.dto.UserRegistrationRequest;
import com.haro.user.dto.UserResponse;
import com.haro.user.entity.User;
import com.haro.user.entity.UserRole;
import com.haro.user.entity.UserStatus;
import com.haro.user.event.UserDeletedEvent;
import com.haro.user.repository.EmailVerificationTokenRepository;
import com.haro.user.repository.PasswordResetTokenRepository;
import com.haro.user.repository.SessionRepository;
import com.haro.user.repository.UserRepository;
import com.haro.user.repository.UserRoleRepository;
import com.haro.user.security.Roles;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
public class UserService {
    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    private static final int UNVERIFIED_ACCOUNT_EXPIRY_HOURS = 24;

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final SessionRepository sessionRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationService emailVerificationService;
    private final OutboxService outboxService;
    private final AuditService auditService;


    @Transactional
    public UserResponse registerUser(UserRegistrationRequest request) {
        Optional<User> existing = userRepository.findByEmailIgnoreCase(request.email());

        if (existing.isPresent()) {
            User stale = existing.get();

            if (stale.getEmailVerifiedAt() != null) {
                throw new ConflictException("Email is already in use");
            }

            boolean withinGracePeriod = stale.getCreatedAt().plusHours(UNVERIFIED_ACCOUNT_EXPIRY_HOURS)
                    .isAfter(OffsetDateTime.now());

            if (withinGracePeriod) {
                throw new ConflictException(
                        "A verification email was already sent. Please check your inbox or try again later.");
            }

            log.info("Removing stale unverified account for email={}", stale.getEmail());
            userRepository.delete(stale);
            userRepository.flush();
        }

        User user = User.builder()
                .email(request.email().toLowerCase())
                .passwordHash(passwordEncoder.encode(request.password()))
                .name(request.name())
                .status(UserStatus.PENDING_VERIFICATION)
                .build();

        User saved = userRepository.save(user);

        userRoleRepository.save(UserRole.builder()
                .user(saved)
                .role(Roles.FAN)
                .build());

        emailVerificationService.createVerificationToken(saved);

        return toResponse(saved, Set.of(Roles.FAN));
    }

    @Transactional(readOnly = true)
    public UserResponse getUser(UUID id) {
        return toResponse(findLiveUser(id));
    }

    @Transactional
    public UserResponse updateProfile(UUID id, UpdateProfileRequest request) {
        User user = findLiveUser(id);

        if (request.name() != null) {
            user.setName(request.name());
        }
        if (request.phone() != null) {
            user.setPhone(request.phone());
        }
        if (request.avatarUrl() != null) {
            user.setAvatarUrl(request.avatarUrl());
        }

        return toResponse(userRepository.save(user));
    }

    /** Changes the password and revokes every session, so stolen refresh tokens stop working. */
    @Transactional
    public void changePassword(UUID id, ChangePasswordRequest request) {
        User user = findLiveUser(id);

        if (user.getPasswordHash() == null ||
                !passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new BadRequestException("Current password is incorrect");
        }

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
        sessionRepository.deleteAllByUser(user);
    }

    /**
     * Deletes the account and personal data (FR-ACC-04). The row is anonymized rather than removed because
     * bookings, payments and tickets in other services reference the user id and must be retained.
     */
    @Transactional
    public void deleteAccount(UUID id, DeleteAccountRequest request) {
        User user = findLiveUser(id);

        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new BadRequestException("Password is incorrect");
        }

        OffsetDateTime now = OffsetDateTime.now();

        sessionRepository.deleteAllByUser(user);
        passwordResetTokenRepository.deleteAllByUser(user);
        emailVerificationTokenRepository.deleteAllByUser(user);

        user.setEmail("deleted-" + user.getId() + "@deleted.invalid");
        user.setName(null);
        user.setPhone(null);
        user.setAvatarUrl(null);
        user.setPasswordHash(null);
        user.setStatus(UserStatus.DELETED);
        user.setDeletedAt(now);
        userRepository.save(user);

        outboxService.saveEvent(OutboxService.USER_EVENTS_TOPIC, OutboxService.AGGREGATE_USER, user.getId(),
                UserDeletedEvent.TYPE, new UserDeletedEvent(user.getId(), now));
        auditService.record(user.getId(), "USER_DELETED_ACCOUNT", AuditService.TARGET_USER, user.getId(), null);

        log.info("User account deleted and anonymized id={}", user.getId());
    }

    /** Finds a user that has not deleted their account. */
    @Transactional(readOnly = true)
    public User findLiveUser(UUID id) {
        return userRepository.findById(id)
                .filter(u -> !UserStatus.DELETED.equals(u.getStatus()))
                .orElseThrow(() -> new NotFoundException("User not found"));
    }

    public Set<String> loadRoles(User user) {
        return userRoleRepository.findByUser(user).stream()
                .map(UserRole::getRole)
                .collect(Collectors.toSet());
    }

    public UserResponse toResponse(User user) {
        return toResponse(user, loadRoles(user));
    }

    public UserResponse toResponse(User user, Set<String> roles) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getPhone(),
                user.getAvatarUrl(),
                user.getStatus(),
                user.getEmailVerifiedAt(),
                user.getCreatedAt(),
                user.getUpdatedAt(),
                roles
        );
    }
}
