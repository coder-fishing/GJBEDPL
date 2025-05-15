package org.example.goodjobbackend.repository;

import org.example.goodjobbackend.model.Employer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EmployerRepository extends JpaRepository<Employer, Long> {
    Optional<Employer> findByUserId(Long userId);
    Optional<Employer> findByCompanyName(String companyName);
    boolean existsByCompanyName(String companyName);
    boolean existsByTaxCode(String taxCode);
    boolean existsByUserId(Long userId);

    @Query("SELECT e FROM Employer e JOIN FETCH e.user WHERE e.user.id = :userId")
    Optional<Employer> findByUserIdWithUser(@Param("userId") Long userId);
    
    @Query("SELECT CASE WHEN COUNT(e) > 0 THEN true ELSE false END FROM Employer e WHERE e.user.email = :email")
    boolean existsByEmail(@Param("email") String email);
} 