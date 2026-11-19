package com.haro.user.repository;

import com.haro.user.entity.EmailVerificationToken;
import com.haro.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, UUID> {
    List<EmailVerificationToken> findByUserAndVerifiedAtIsNullOrderByCreatedAtDesc(User user);

    @Modifying(flushAutomatically = true)
    @Query("delete from EmailVerificationToken t where t.user = :user")
    int deleteAllByUser(@Param("user") User user);
}
