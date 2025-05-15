package org.example.goodjobbackend.controller;

import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.model.Notification;
import org.example.goodjobbackend.model.NotificationType;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.JobApplication;
import org.example.goodjobbackend.service.NotificationService;
import org.example.goodjobbackend.service.UserService;
import org.example.goodjobbackend.service.JobApplicationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class NotificationController {
    private final NotificationService notificationService;
    private final UserService userService;
    private final JobApplicationService jobApplicationService;

    @PostMapping("/employer")
    public ResponseEntity<Notification> createEmployerNotification(
            @RequestParam Long employerId,
            @RequestParam String applicantName,
            @RequestParam String jobTitle,
            @RequestParam Long applicationId) {
        
        User employer = userService.getUserById(employerId);
        JobApplication application = jobApplicationService.getJobApplicationById(applicationId);
        
        Notification notification = notificationService.notifyNewApplication(
            employer, 
            applicantName, 
            jobTitle, 
            application
        );
        
        return ResponseEntity.ok(notification);
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<Notification>> getUserNotifications(@PathVariable Long userId) {
        List<Notification> notifications = notificationService.getUserNotifications(userId);
        return ResponseEntity.ok(notifications);
    }

    @GetMapping("/user/{userId}/unread")
    public ResponseEntity<List<Notification>> getUnreadNotifications(@PathVariable Long userId) {
        List<Notification> notifications = notificationService.getUnreadNotifications(userId);
        return ResponseEntity.ok(notifications);
    }

    @GetMapping("/user/{userId}/unread/count")
    public ResponseEntity<Long> getUnreadCount(@PathVariable Long userId) {
        long count = notificationService.getUnreadCount(userId);
        return ResponseEntity.ok(count);
    }

    @PutMapping("/{notificationId}/read")
    public ResponseEntity<Void> markAsRead(@PathVariable Long notificationId) {
        notificationService.markAsRead(notificationId);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/user/{userId}/read-all")
    public ResponseEntity<Void> markAllAsRead(@PathVariable Long userId) {
        notificationService.markAllAsRead(userId);
        return ResponseEntity.ok().build();
    }
} 