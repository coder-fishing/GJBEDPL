package org.example.goodjobbackend.controller;

import org.example.goodjobbackend.dto.AdminNotificationDTO;
import org.example.goodjobbackend.model.AdminAction;
import org.example.goodjobbackend.model.AdminNotification;
import org.example.goodjobbackend.model.Job;
import org.example.goodjobbackend.model.JobStatus;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.service.AdminNotificationService;
import org.example.goodjobbackend.service.JobService;
import org.example.goodjobbackend.service.TestDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/test")
public class TestApiController {

    @Autowired
    private AdminNotificationService adminNotificationService;
    
    @Autowired
    private TestDataService testDataService;
    
    @Autowired
    private JobService jobService;
    
    private Random random = new Random();
    
    @PostMapping("/admin-notifications/sample")
    public ResponseEntity<List<AdminNotificationDTO>> createSampleNotifications() {
        User adminUser = testDataService.getMockAdminUser();
        User employerUser = testDataService.getMockEmployerUser();
        
        List<Job> jobs;
        try {
            jobs = jobService.getAllJobs();  
            if (jobs.isEmpty()) {
                return ResponseEntity.badRequest().body(null);
            }
        } catch (Exception e) {
            // Create mock jobs if can't get from repository
            jobs = createMockJobs();
        }
        
        List<AdminNotification> notifications = new ArrayList<>();
        
        // Create sample notifications with mixed read/unread status
        
        // Job creation notification - unread (CREATE type is unread by default)
        AdminNotification createNotification = adminNotificationService.createNotificationWithTimestamp(
                AdminAction.CREATE, 
                employerUser, 
                "Công việc mới được tạo: Senior Developer",
                101L,
                "Senior Developer",
                LocalDateTime.now().minusHours(1)
        );
        notifications.add(createNotification);
        
        // Job update notification - unread
        AdminNotification updateNotification = adminNotificationService.createNotificationWithTimestamp(
                AdminAction.UPDATE, 
                employerUser, 
                "Công việc được cập nhật: Frontend Developer",
                105L,
                "Frontend Developer",
                LocalDateTime.now().minusDays(1)
        );
        updateNotification.setRead(false);
        // Save the updated notification
        AdminNotification savedUpdateNotification = adminNotificationService.createNotificationWithTimestamp(
                updateNotification.getType(),
                updateNotification.getUser(),
                updateNotification.getDescription(),
                updateNotification.getJobId(),
                updateNotification.getJobTitle(),
                updateNotification.getTimestamp()
        );
        notifications.add(savedUpdateNotification);
        
        // Job approval notification - read
        AdminNotification approveNotification = adminNotificationService.createNotificationWithTimestamp(
                AdminAction.APPROVE, 
                adminUser, 
                "Công việc được phê duyệt: DevOps Engineer",
                107L,
                "DevOps Engineer",
                LocalDateTime.now().minusDays(3)
        );
        approveNotification.setRead(true);
        // Save the updated notification
        AdminNotification savedApproveNotification = adminNotificationService.createNotificationWithTimestamp(
                approveNotification.getType(),
                approveNotification.getUser(),
                approveNotification.getDescription(),
                approveNotification.getJobId(),
                approveNotification.getJobTitle(),
                approveNotification.getTimestamp()
        );
        savedApproveNotification.setRead(true);
        notifications.add(savedApproveNotification);
        
        // Job rejection notification - read
        AdminNotification rejectNotification = adminNotificationService.createNotificationWithTimestamp(
                AdminAction.REJECT, 
                adminUser, 
                "Công việc bị từ chối: Mobile Developer. Lý do: Không đủ thông tin",
                110L,
                "Mobile Developer",
                LocalDateTime.now().minusDays(6)
        );
        rejectNotification.setRead(true);
        // Save the updated notification
        AdminNotification savedRejectNotification = adminNotificationService.createNotificationWithTimestamp(
                rejectNotification.getType(),
                rejectNotification.getUser(),
                rejectNotification.getDescription(),
                rejectNotification.getJobId(),
                rejectNotification.getJobTitle(),
                rejectNotification.getTimestamp()
        );
        savedRejectNotification.setRead(true);
        notifications.add(savedRejectNotification);
        
        // Convert to DTOs
        List<AdminNotificationDTO> dtoList = notifications.stream()
                .map(AdminNotificationDTO::fromEntity)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(dtoList);
    }
    
    @PostMapping("/jobs/{jobId}/process")
    public ResponseEntity<Job> processJobForTesting(
            @PathVariable Long jobId,
            @RequestParam JobStatus newStatus,
            @RequestParam(required = false) String rejectionReason) {
        try {
            Job processedJob = jobService.processJobForTesting(jobId, newStatus, rejectionReason);
            return ResponseEntity.ok(processedJob);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(null);
        }
    }
    
    private List<Job> createMockJobs() {
        List<Job> mockJobs = new ArrayList<>();
        
        Job job1 = new Job();
        job1.setJobId(101L);
        job1.setTitle("Senior Developer");
        mockJobs.add(job1);
        
        Job job2 = new Job();
        job2.setJobId(105L);
        job2.setTitle("Frontend Developer");
        mockJobs.add(job2);
        
        Job job3 = new Job();
        job3.setJobId(107L);
        job3.setTitle("DevOps Engineer");
        mockJobs.add(job3);
        
        Job job4 = new Job();
        job4.setJobId(110L);
        job4.setTitle("Mobile Developer");
        mockJobs.add(job4);
        
        return mockJobs;
    }
} 