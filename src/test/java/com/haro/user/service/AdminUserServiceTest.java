package com.haro.user.service;

import com.haro.common.web.BadRequestException;
import com.haro.user.dto.UpdateUserRolesRequest;
import com.haro.user.dto.UpdateUserStatusRequest;
import com.haro.user.entity.User;
import com.haro.user.entity.UserRole;
import com.haro.user.entity.UserStatus;
import com.haro.user.repository.SessionRepository;
import com.haro.user.repository.UserRepository;
import com.haro.user.repository.UserRoleRepository;
import com.haro.user.security.Roles;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdminUserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private UserRoleRepository userRoleRepository;
    @Mock
    private SessionRepository sessionRepository;
    @Mock
    private UserService userService;
    @Mock
    private AuditService auditService;

    @InjectMocks
    private AdminUserService adminUserService;

    private final UUID adminId = UUID.randomUUID();

    private User user(String status) {
        return User.builder().id(UUID.randomUUID()).email("user@test.com").status(status).build();
    }

    @Test
    void suspendRevokesSessionsAndAudits() {
        User user = user(UserStatus.ACTIVE);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        adminUserService.updateStatus(adminId, user.getId(), new UpdateUserStatusRequest("SUSPENDED", "fraud"));

        assertEquals(UserStatus.SUSPENDED, user.getStatus());
        verify(sessionRepository).deleteAllByUser(user);
        verify(auditService).record(eq(adminId), eq("USER_STATUS_CHANGED"), eq(AuditService.TARGET_USER),
                eq(user.getId()), anyString());
    }

    @Test
    void reactivateRestoresPendingVerificationWhenEmailUnverified() {
        User user = user(UserStatus.SUSPENDED);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        adminUserService.updateStatus(adminId, user.getId(), new UpdateUserStatusRequest("ACTIVE", null));

        assertEquals(UserStatus.PENDING_VERIFICATION, user.getStatus());
        verify(sessionRepository, never()).deleteAllByUser(any());
    }

    @Test
    void reactivateRestoresActiveWhenEmailVerified() {
        User user = user(UserStatus.SUSPENDED);
        user.setEmailVerifiedAt(OffsetDateTime.now());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        adminUserService.updateStatus(adminId, user.getId(), new UpdateUserStatusRequest("ACTIVE", null));

        assertEquals(UserStatus.ACTIVE, user.getStatus());
    }

    @Test
    void adminCannotSuspendThemselves() {
        assertThrows(BadRequestException.class, () -> adminUserService.updateStatus(
                adminId, adminId, new UpdateUserStatusRequest("SUSPENDED", null)));
        verifyNoInteractions(userRepository, auditService);
    }

    @Test
    void updateRolesReplacesRoleSetAndAudits() {
        User user = user(UserStatus.ACTIVE);
        UserRole fan = UserRole.builder().user(user).role(Roles.FAN).build();
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRoleRepository.findByUser(user)).thenReturn(List.of(fan));

        adminUserService.updateRoles(adminId, user.getId(), new UpdateUserRolesRequest(Set.of(Roles.ORGANIZER)));

        verify(userRoleRepository).deleteAll(List.of(fan));
        ArgumentCaptor<UserRole> added = ArgumentCaptor.forClass(UserRole.class);
        verify(userRoleRepository).save(added.capture());
        assertEquals(Roles.ORGANIZER, added.getValue().getRole());
        verify(auditService).record(eq(adminId), eq("USER_ROLES_CHANGED"), eq(AuditService.TARGET_USER),
                eq(user.getId()), anyString());
    }

    @Test
    void updateRolesRejectsUnknownRole() {
        assertThrows(BadRequestException.class, () -> adminUserService.updateRoles(
                adminId, UUID.randomUUID(), new UpdateUserRolesRequest(Set.of("ROLE_GOD"))));
        verifyNoInteractions(userRoleRepository, auditService);
    }

    @Test
    void adminCannotRemoveOwnAdminRole() {
        assertThrows(BadRequestException.class, () -> adminUserService.updateRoles(
                adminId, adminId, new UpdateUserRolesRequest(Set.of(Roles.FAN))));
    }
}
