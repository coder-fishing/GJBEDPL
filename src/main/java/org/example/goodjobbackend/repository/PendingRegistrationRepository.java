package org.example.goodjobbackend.repository;

import org.example.goodjobbackend.model.PendingRegistration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PendingRegistrationRepository extends JpaRepository<PendingRegistration, Long> {
    Optional<PendingRegistration> findByEmailAndVerificationCodeAndUsedFalse(String email, String verificationCode);
    Optional<PendingRegistration> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

} 