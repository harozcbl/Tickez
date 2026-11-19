package com.haro.user.controller;

import com.haro.user.dto.UpdateUserRolesRequest;
import com.haro.user.dto.UpdateUserStatusRequest;
import com.haro.user.dto.UserResponse;
import com.haro.user.service.AdminUserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Account administration. Access rules are in {@code SecurityConfig}: reads need ADMIN or SUPPORT, changes need ADMIN.
 */
@RestController
@RequestMapping("/api/admin/users")
@RequiredArgsConstructor
public class AdminUserController {

    private final AdminUserService adminUserService;

    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> getUser(@PathVariable UUID id) {
        return ResponseEntity.ok(adminUserService.getUser(id));
    }

    @PutMapping("/{id}/status")
    public ResponseEntity<UserResponse> updateStatus(
            @AuthenticationPrincipal UUID actorId,
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserStatusRequest request
    ) {
        return ResponseEntity.ok(adminUserService.updateStatus(actorId, id, request));
    }

    @PutMapping("/{id}/roles")
    public ResponseEntity<UserResponse> updateRoles(
            @AuthenticationPrincipal UUID actorId,
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserRolesRequest request
    ) {
        return ResponseEntity.ok(adminUserService.updateRoles(actorId, id, request));
    }
}
