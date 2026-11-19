package com.haro.user.repository;

import com.haro.user.entity.PasswordResetToken;
import com.haro.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.UUID;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    /** Marks every outstanding reset token of the user as used, so only the newest one is valid. */
    @Modifying(flushAutomatically = true)
    @Query("update PasswordResetToken t set t.usedAt = :now where t.user = :user and t.usedAt is null")
    int invalidateUnusedTokens(@Param("user") User user, @Param("now") OffsetDateTime now);

    @Modifying(flushAutomatically = true)
    @Query("delete from PasswordResetToken t where t.user = :user")
    int deleteAllByUser(@Param("user") User user);
}
