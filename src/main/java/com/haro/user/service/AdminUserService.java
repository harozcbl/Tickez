package com.haro.user.service;

import com.haro.common.web.BadRequestException;
import com.haro.common.web.ConflictException;
import com.haro.common.web.NotFoundException;
import com.haro.user.dto.UpdateUserRolesRequest;
import com.haro.user.dto.UpdateUserStatusRequest;
import com.haro.user.dto.UserResponse;
import com.haro.user.entity.User;
import com.haro.user.entity.UserRole;
import com.haro.user.entity.UserStatus;
import com.haro.user.repository.SessionRepository;
import com.haro.user.repository.UserRepository;
import com.haro.user.repository.UserRoleRepository;
import com.haro.user.security.Roles;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Platform admin / support operations on accounts (FR-ADM-04). Every change is audited (FR-ADM-07).
 */
@Service
@RequiredArgsConstructor
public class AdminUserService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final SessionRepository sessionRepository;
    private final UserService userService;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public UserResponse getUser(UUID id) {
        return userService.toResponse(findUser(id));
    }

    /** Suspends (and logs out) or re-activates an account. */
    @Transactional
    public UserResponse updateStatus(UUID actorId, UUID id, UpdateUserStatusRequest request) {
        if (actorId.equals(id)) {
            throw new BadRequestException("Admins cannot change their own status");
        }

        User user = findUser(id);
        if (UserStatus.DELETED.equals(user.getStatus())) {
            throw new ConflictException("Account has been deleted");
        }

        String previous = user.getStatus();
        String next = UserStatus.SUSPENDED.equals(request.status())
                ? UserStatus.SUSPENDED
                : (user.getEmailVerifiedAt() != null ? UserStatus.ACTIVE : UserStatus.PENDING_VERIFICATION);

        user.setStatus(next);
        userRepository.save(user);

        if (UserStatus.SUSPENDED.equals(next)) {
            sessionRepository.deleteAllByUser(user);
        }

        auditService.record(actorId, "USER_STATUS_CHANGED", AuditService.TARGET_USER, id,
                previous + " -> " + next + (request.reason() != null ? "; reason: " + request.reason() : ""));

        return userService.toResponse(user);
    }

    /** Replaces the user's roles. Takes effect on the user's next login or token refresh. */
    @Transactional
    public UserResponse updateRoles(UUID actorId, UUID id, UpdateUserRolesRequest request) {
        Set<String> requested = new TreeSet<>(request.roles());
        Set<String> unknown = new TreeSet<>(requested);
        unknown.removeAll(Roles.ALL);
        if (!unknown.isEmpty()) {
            throw new BadRequestException("Unknown roles: " + unknown);
        }
        if (actorId.equals(id) && !requested.contains(Roles.ADMIN)) {
            throw new BadRequestException("Admins cannot remove their own admin role");
        }

        User user = findUser(id);
        if (UserStatus.DELETED.equals(user.getStatus())) {
            throw new ConflictException("Account has been deleted");
        }

        List<UserRole> current = userRoleRepository.findByUser(user);
        Set<String> previous = new TreeSet<>(current.stream().map(UserRole::getRole).toList());

        userRoleRepository.deleteAll(current.stream().filter(r -> !requested.contains(r.getRole())).toList());
        requested.stream()
                .filter(role -> !previous.contains(role))
                .forEach(role -> userRoleRepository.save(UserRole.builder().user(user).role(role).build()));

        auditService.record(actorId, "USER_ROLES_CHANGED", AuditService.TARGET_USER, id,
                previous + " -> " + requested);

        return userService.toResponse(user, requested);
    }

    private User findUser(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("User not found"));
    }
}
