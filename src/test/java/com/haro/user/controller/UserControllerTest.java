package com.haro.user.controller;

import com.haro.user.dto.ChangePasswordRequest;
import com.haro.user.dto.DeleteAccountRequest;
import com.haro.user.dto.UpdateProfileRequest;
import com.haro.user.dto.UserRegistrationRequest;
import com.haro.user.dto.UserResponse;
import com.haro.user.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    private static UserResponse user(UUID id, String name) {
        return new UserResponse(id, "user@test.com", name, null, null, "ACTIVE", null, null, null, Set.of("ROLE_FAN"));
    }

    @Test
    void registerReturnsCreatedUser() {
        UserRegistrationRequest request = new UserRegistrationRequest("user@test.com", "secret123", "User");
        UserResponse expected = user(UUID.randomUUID(), "User");
        when(userService.registerUser(request)).thenReturn(expected);

        ResponseEntity<UserResponse> response = userController.register(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(expected, response.getBody());
    }

    @Test
    void getCurrentUserUsesAuthenticatedUserId() {
        UUID userId = UUID.randomUUID();
        UserResponse expected = user(userId, "User");
        when(userService.getUser(userId)).thenReturn(expected);

        ResponseEntity<UserResponse> response = userController.getCurrentUser(userId);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(expected, response.getBody());
    }

    @Test
    void updateProfileUsesAuthenticatedUserId() {
        UUID userId = UUID.randomUUID();
        UpdateProfileRequest request = new UpdateProfileRequest("Updated Name", "123456789", null);
        UserResponse expected = user(userId, "Updated Name");
        when(userService.updateProfile(userId, request)).thenReturn(expected);

        ResponseEntity<UserResponse> response = userController.updateProfile(userId, request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(expected, response.getBody());
    }

    @Test
    void changePasswordReturnsNoContent() {
        UUID userId = UUID.randomUUID();
        ChangePasswordRequest request = new ChangePasswordRequest("oldPassword123", "newPassword123");

        ResponseEntity<Void> response = userController.changePassword(userId, request);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(userService).changePassword(userId, request);
    }

    @Test
    void deleteAccountReturnsNoContent() {
        UUID userId = UUID.randomUUID();
        DeleteAccountRequest request = new DeleteAccountRequest("secret123");

        ResponseEntity<Void> response = userController.deleteAccount(userId, request);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(userService).deleteAccount(userId, request);
    }
}
