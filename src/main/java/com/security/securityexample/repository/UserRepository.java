package com.security.securityexample.repository;

import com.security.securityexample.entity.UserEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Boolean existsByUsername(String username);

    Optional<UserEntity> findByUsername(String username);
}
