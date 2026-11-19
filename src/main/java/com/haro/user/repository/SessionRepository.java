package com.haro.user.repository;

import com.haro.user.entity.Session;
import com.haro.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface SessionRepository extends JpaRepository<Session, UUID> {

    @Modifying(flushAutomatically = true)
    @Query("delete from Session s where s.id = :id and s.user.id = :userId")
    int deleteByIdAndUserId(@Param("id") UUID id, @Param("userId") UUID userId);

    @Modifying(flushAutomatically = true)
    @Query("delete from Session s where s.user = :user")
    int deleteAllByUser(@Param("user") User user);
}
