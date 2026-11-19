package com.haro.user.service;

import com.haro.common.web.BadRequestException;
import com.haro.user.config.JwtProperties;
import com.haro.user.dto.AuthResponse;
import com.haro.user.dto.LoginRequest;
import com.haro.user.dto.RefreshTokenRequest;
import com.haro.user.entity.Session;
import com.haro.user.entity.User;
import com.haro.user.entity.UserStatus;
import com.haro.user.repository.SessionRepository;
import com.haro.user.repository.UserRepository;
import com.haro.user.security.Roles;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserService userService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private SessionRepository sessionRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private JwtProperties jwtProperties;

    @InjectMocks
    private AuthService authService;

    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("user@test.com")
                .passwordHash("hash")
                .status(UserStatus.PENDING_VERIFICATION)
                .build();
    }

    private void stubSessionCreation() {
        when(userService.loadRoles(user)).thenReturn(Set.of(Roles.FAN));
        when(passwordEncoder.encode(anyString())).thenReturn("refresh-hash");
        when(sessionRepository.save(any(Session.class))).thenAnswer(inv -> {
            Session s = inv.getArgument(0);
            s.setId(UUID.randomUUID());
            return s;
        });
        when(jwtService.generateAccessToken(any(), any(), any(), anyBoolean())).thenReturn("access");
    }

    @Test
    void loginAllowsUnverifiedUserWithEmailVerifiedFalseClaim() {
        when(userRepository.findByEmailIgnoreCase("user@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
        stubSessionCreation();

        AuthResponse response = authService.login(new LoginRequest("user@test.com", "secret"));

        assertEquals("access", response.accessToken());
        verify(jwtService).generateAccessToken(user.getId(), "user@test.com", Set.of(Roles.FAN), false);
    }

    @Test
    void loginEmitsEmailVerifiedTrueForVerifiedUser() {
        user.setEmailVerifiedAt(OffsetDateTime.now());
        user.setStatus(UserStatus.ACTIVE);
        when(userRepository.findByEmailIgnoreCase("user@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
        stubSessionCreation();

        authService.login(new LoginRequest("user@test.com", "secret"));

        verify(jwtService).generateAccessToken(user.getId(), "user@test.com", Set.of(Roles.FAN), true);
    }

    @Test
    void loginWithUnknownEmailGivesSameErrorAsWrongPassword() {
        when(userRepository.findByEmailIgnoreCase("nobody@test.com")).thenReturn(Optional.empty());
        when(userRepository.findByEmailIgnoreCase("user@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);

        BadRequestException unknown = assertThrows(BadRequestException.class,
                () -> authService.login(new LoginRequest("nobody@test.com", "secret")));
        BadRequestException wrong = assertThrows(BadRequestException.class,
                () -> authService.login(new LoginRequest("user@test.com", "wrong")));

        assertEquals(AuthService.INVALID_CREDENTIALS, unknown.getMessage());
        assertEquals(unknown.getMessage(), wrong.getMessage());
        verifyNoInteractions(sessionRepository);
    }

    @Test
    void loginRejectsSuspendedUser() {
        user.setStatus(UserStatus.SUSPENDED);
        when(userRepository.findByEmailIgnoreCase("user@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "hash")).thenReturn(true);

        BadRequestException ex = assertThrows(BadRequestException.class,
                () -> authService.login(new LoginRequest("user@test.com", "secret")));

        assertEquals(AuthService.ACCOUNT_SUSPENDED, ex.getMessage());
        verifyNoInteractions(sessionRepository);
    }

    @Test
    void refreshRejectsSuspendedUserAndDeletesSession() {
        user.setStatus(UserStatus.SUSPENDED);
        Session session = Session.builder()
                .id(UUID.randomUUID())
                .user(user)
                .refreshTokenHash("refresh-hash")
                .expiresAt(OffsetDateTime.now().plusDays(1))
                .build();
        when(sessionRepository.findById(session.getId())).thenReturn(Optional.of(session));
        when(passwordEncoder.matches("refresh", "refresh-hash")).thenReturn(true);

        assertThrows(BadRequestException.class,
                () -> authService.refresh(new RefreshTokenRequest(session.getId(), "refresh")));

        verify(sessionRepository).delete(session);
        verify(jwtService, never()).generateAccessToken(any(), any(), any(), anyBoolean());
    }

    @Test
    void logoutOnlyDeletesSessionOwnedByCaller() {
        UUID sessionId = UUID.randomUUID();

        authService.logout(user.getId(), sessionId);

        verify(sessionRepository).deleteByIdAndUserId(eq(sessionId), eq(user.getId()));
        verify(sessionRepository, never()).deleteById(any());
    }
}
