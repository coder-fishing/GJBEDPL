package org.example.goodjobbackend.repository;

import org.example.goodjobbackend.model.SavedJob;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SavedJobRepository extends JpaRepository<SavedJob, Long> {
    
    /**
     * Find all saved jobs for a specific user
     */
    List<SavedJob> findByUserId(Long userId);
    
    /**
     * Find a saved job by user and job ids
     */
    Optional<SavedJob> findByUserIdAndJobJobId(Long userId, Long jobId);
    
    /**
     * Check if a job is saved by a user
     */
    boolean existsByUserIdAndJobJobId(Long userId, Long jobId);
    
    /**
     * Delete a saved job by user and job ids
     */
    void deleteByUserIdAndJobJobId(Long userId, Long jobId);
} 