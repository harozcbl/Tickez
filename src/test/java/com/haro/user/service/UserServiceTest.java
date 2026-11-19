package com.haro.user.service;

import com.haro.common.web.BadRequestException;
import com.haro.common.web.NotFoundException;
import com.haro.user.dto.ChangePasswordRequest;
import com.haro.user.dto.DeleteAccountRequest;
import com.haro.user.dto.UserRegistrationRequest;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private UserRoleRepository userRoleRepository;
    @Mock
    private SessionRepository sessionRepository;
    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;
    @Mock
    private EmailVerificationTokenRepository emailVerificationTokenRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private EmailVerificationService emailVerificationService;
    @Mock
    private OutboxService outboxService;
    @Mock
    private AuditService auditService;

    @InjectMocks
    private UserService userService;

    private User activeUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .email("user@test.com")
                .name("User")
                .phone("123")
                .avatarUrl("https://example.com/a.png")
                .passwordHash("hash")
                .status(UserStatus.ACTIVE)
                .build();
    }

    @Test
    void registerCreatesPendingFanAndSendsVerificationEmail() {
        when(userRepository.findByEmailIgnoreCase("New@Test.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("secret123")).thenReturn("hash");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        var response = userService.registerUser(new UserRegistrationRequest("New@Test.com", "secret123", "New"));

        assertEquals("new@test.com", response.email());
        assertEquals(UserStatus.PENDING_VERIFICATION, response.status());
        ArgumentCaptor<UserRole> role = ArgumentCaptor.forClass(UserRole.class);
        verify(userRoleRepository).save(role.capture());
        assertEquals(Roles.FAN, role.getValue().getRole());
        verify(emailVerificationService).createVerificationToken(any(User.class));
    }

    @Test
    void changePasswordRevokesAllSessions() {
        User user = activeUser();
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("oldPassword1", "hash")).thenReturn(true);
        when(passwordEncoder.encode("newPassword1")).thenReturn("new-hash");

        userService.changePassword(user.getId(), new ChangePasswordRequest("oldPassword1", "newPassword1"));

        assertEquals("new-hash", user.getPasswordHash());
        verify(sessionRepository).deleteAllByUser(user);
    }

    @Test
    void deleteAccountAnonymizesUserRevokesAccessAndPublishesEvent() {
        User user = activeUser();
        UUID id = user.getId();
        when(userRepository.findById(id)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret123", "hash")).thenReturn(true);

        userService.deleteAccount(id, new DeleteAccountRequest("secret123"));

        assertEquals("deleted-" + id + "@deleted.invalid", user.getEmail());
        assertNull(user.getName());
        assertNull(user.getPhone());
        assertNull(user.getAvatarUrl());
        assertNull(user.getPasswordHash());
        assertEquals(UserStatus.DELETED, user.getStatus());
        assertNotNull(user.getDeletedAt());
        verify(sessionRepository).deleteAllByUser(user);
        verify(passwordResetTokenRepository).deleteAllByUser(user);
        verify(emailVerificationTokenRepository).deleteAllByUser(user);
        verify(outboxService).saveEvent(eq(OutboxService.USER_EVENTS_TOPIC), eq(OutboxService.AGGREGATE_USER),
                eq(id), eq(UserDeletedEvent.TYPE), any(UserDeletedEvent.class));
        verify(auditService).record(eq(id), eq("USER_DELETED_ACCOUNT"), eq(AuditService.TARGET_USER), eq(id), any());
    }

    @Test
    void deleteAccountRequiresCorrectPassword() {
        User user = activeUser();
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);

        assertThrows(BadRequestException.class,
                () -> userService.deleteAccount(user.getId(), new DeleteAccountRequest("wrong")));

        assertEquals(UserStatus.ACTIVE, user.getStatus());
        verifyNoInteractions(sessionRepository, outboxService);
    }

    @Test
    void deletedUserIsNotFound() {
        User user = activeUser();
        user.setStatus(UserStatus.DELETED);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        assertThrows(NotFoundException.class, () -> userService.getUser(user.getId()));
    }
}
