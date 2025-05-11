package org.example.goodjobbackend.service;

import org.example.goodjobbackend.dto.SavedJobDTO;
import org.example.goodjobbackend.model.Job;
import org.example.goodjobbackend.model.SavedJob;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.repository.JobRepository;
import org.example.goodjobbackend.repository.SavedJobRepository;
import org.example.goodjobbackend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class SavedJobService {

    private final SavedJobRepository savedJobRepository;
    private final UserRepository userRepository;
    private final JobRepository jobRepository;

    @Autowired
    public SavedJobService(SavedJobRepository savedJobRepository, 
                          UserRepository userRepository, 
                          JobRepository jobRepository) {
        this.savedJobRepository = savedJobRepository;
        this.userRepository = userRepository;
        this.jobRepository = jobRepository;
    }

    /**
     * Toggle save/unsave a job for a user
     * @param userId the user ID
     * @param jobId the job ID
     * @return true if job was saved, false if it was unsaved
     */
    @Transactional
    public boolean toggleSaveJob(Long userId, Long jobId) {
        // Check if user and job exist
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        Job job = jobRepository.findById(jobId)
                .orElseThrow(() -> new RuntimeException("Job not found"));
        
        // Check if job is already saved
        boolean jobAlreadySaved = savedJobRepository.existsByUserIdAndJobJobId(userId, jobId);
        
        if (jobAlreadySaved) {
            // Unsave the job
            savedJobRepository.deleteByUserIdAndJobJobId(userId, jobId);
            return false;
        } else {
            // Save the job
            SavedJob savedJob = new SavedJob();
            savedJob.setUser(user);
            savedJob.setJob(job);
            savedJobRepository.save(savedJob);
            return true;
        }
    }
    
    /**
     * Check if a job is saved by a user
     * @param userId the user ID
     * @param jobId the job ID
     * @return true if the job is saved by the user, false otherwise
     */
    public boolean isJobSavedByUser(Long userId, Long jobId) {
        return savedJobRepository.existsByUserIdAndJobJobId(userId, jobId);
    }
    
    /**
     * Get all saved jobs for a user
     * @param userId the user ID
     * @return a list of saved jobs
     */
    public List<SavedJobDTO> getSavedJobsByUser(Long userId) {
        List<SavedJob> savedJobs = savedJobRepository.findByUserId(userId);
        
        return savedJobs.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }
    
    /**
     * Convert a SavedJob entity to a SavedJobDTO
     * @param savedJob the SavedJob entity
     * @return a SavedJobDTO
     */
    private SavedJobDTO convertToDTO(SavedJob savedJob) {
        SavedJobDTO dto = new SavedJobDTO();
        dto.setId(savedJob.getId());
        dto.setJobId(savedJob.getJob().getJobId());
        dto.setTitle(savedJob.getJob().getTitle());
        
        // Get company name from employer if available
        if (savedJob.getJob().getEmployer() != null) {
            dto.setCompanyName(savedJob.getJob().getEmployer().getCompanyName());
        }
        
        dto.setLocation(savedJob.getJob().getLocation());
        
        if (savedJob.getJob().getJobType() != null) {
            dto.setJobType(savedJob.getJob().getJobType().toString());
        }
        
        dto.setSalaryMin(savedJob.getJob().getSalaryMin());
        dto.setSalaryMax(savedJob.getJob().getSalaryMax());
        dto.setSalaryCurrency(savedJob.getJob().getSalaryCurrency());
        dto.setSavedAt(savedJob.getSavedAt());
        dto.setImageUrl(savedJob.getJob().getImageUrl());
        dto.setPostedAt(savedJob.getJob().getPostedAt());
        dto.setExpireAt(savedJob.getJob().getExpireAt());
        
        return dto;
    }
} 