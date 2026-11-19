package com.haro.user.service;

import com.haro.user.entity.AuditLog;
import com.haro.user.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditService {

    public static final String TARGET_USER = "USER";

    private final AuditLogRepository auditLogRepository;

    /** Writes an audit entry in the caller's transaction, so it is rolled back together with the audited change. */
    @Transactional
    public void record(UUID actorId, String action, String targetType, UUID targetId, String details) {
        auditLogRepository.save(AuditLog.builder()
                .actorId(actorId)
                .action(action)
                .targetType(targetType)
                .targetId(targetId)
                .details(details)
                .build());
    }
}
