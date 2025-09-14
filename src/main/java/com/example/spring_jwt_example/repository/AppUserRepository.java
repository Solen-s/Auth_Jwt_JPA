package com.example.spring_jwt_example.repository;

import com.example.spring_jwt_example.model.dto.AppUserDTO;
import com.example.spring_jwt_example.model.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByEmail(String email);
    Optional<AppUser> findByUsername(String username);

    // Optional: find by username OR email in one query
    Optional<AppUser> findByUsernameOrEmail(String username, String email);
}
