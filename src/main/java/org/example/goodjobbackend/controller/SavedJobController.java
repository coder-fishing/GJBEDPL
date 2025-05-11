package org.example.goodjobbackend.controller;

import org.example.goodjobbackend.dto.SavedJobDTO;
import org.example.goodjobbackend.service.SavedJobService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/saved-jobs")
public class SavedJobController {

    private final SavedJobService savedJobService;

    @Autowired
    public SavedJobController(SavedJobService savedJobService) {
        this.savedJobService = savedJobService;
    }

    /**
     * Toggle save/unsave a job for a specific user
     * @param jobId the job ID
     * @param userId the user ID
     * @return a response with message and saved status
     */
    @PostMapping("/toggle/{jobId}/user/{userId}")
    public ResponseEntity<Map<String, Object>> toggleSaveJob(
            @PathVariable Long jobId,
            @PathVariable Long userId) {
        
        boolean isSaved = savedJobService.toggleSaveJob(userId, jobId);
        
        Map<String, Object> response = new HashMap<>();
        response.put("saved", isSaved);
        response.put("message", isSaved ? "Job saved successfully" : "Job unsaved successfully");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Check if a job is saved by a specific user
     * @param jobId the job ID
     * @param userId the user ID
     * @return true if the job is saved, false otherwise
     */
    @GetMapping("/check/{jobId}/user/{userId}")
    public ResponseEntity<Map<String, Boolean>> isJobSaved(
            @PathVariable Long jobId,
            @PathVariable Long userId) {
        
        boolean isSaved = savedJobService.isJobSavedByUser(userId, jobId);
        
        Map<String, Boolean> response = new HashMap<>();
        response.put("saved", isSaved);
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Get all saved jobs for a specific user
     * @param userId the user ID
     * @return a list of saved jobs
     */
    @GetMapping("/user/{userId}")
    public ResponseEntity<List<SavedJobDTO>> getSavedJobs(@PathVariable Long userId) {
        List<SavedJobDTO> savedJobs = savedJobService.getSavedJobsByUser(userId);
        return ResponseEntity.ok(savedJobs);
    }
} 