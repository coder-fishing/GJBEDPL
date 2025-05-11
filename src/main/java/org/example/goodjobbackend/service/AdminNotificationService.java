package org.example.goodjobbackend.service;

import jakarta.transaction.Transactional;
import org.example.goodjobbackend.model.AdminAction;
import org.example.goodjobbackend.model.AdminNotification;
import org.example.goodjobbackend.model.Job;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.repository.AdminNotificationRepository;
import org.example.goodjobbackend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AdminNotificationService {

    @Autowired
    private AdminNotificationRepository adminNotificationRepository;
    
    @Autowired
    private UserRepository userRepository;

    public AdminNotification createNotification(AdminAction actionType, Job job, User user, String description) {
        AdminNotification notification = new AdminNotification();
        notification.setType(actionType);
        notification.setJobId(job.getJobId());
        notification.setJobTitle(job.getTitle());
        notification.setTimestamp(LocalDateTime.now());
        notification.setUsername(user.getUsername());
        notification.setUser(user);
        notification.setDescription(description);
        
        // Set notifications of type CREATE as unread by default
        notification.setRead(actionType != AdminAction.CREATE);
        
        return adminNotificationRepository.save(notification);
    }
    
    public AdminNotification createNotificationWithoutJob(AdminAction actionType, User user, String description) {
        AdminNotification notification = new AdminNotification();
        notification.setType(actionType);
        notification.setTimestamp(LocalDateTime.now());
        notification.setUsername(user.getUsername());
        notification.setUser(user);
        notification.setDescription(description);
        
        // Set notifications of type CREATE as unread by default
        notification.setRead(actionType != AdminAction.CREATE);
        
        return adminNotificationRepository.save(notification);
    }
    
    // For testing: Create with specific timestamp
    public AdminNotification createNotificationWithTimestamp(
            AdminAction actionType, User user, String description, 
            Long jobId, String jobTitle, LocalDateTime timestamp) {
        
        AdminNotification notification = new AdminNotification();
        notification.setType(actionType);
        notification.setJobId(jobId);
        notification.setJobTitle(jobTitle);
        notification.setTimestamp(timestamp);
        notification.setUsername(user.getUsername());
        notification.setUser(user);
        notification.setDescription(description);
        
        // Set notifications of type CREATE as unread by default
        notification.setRead(actionType != AdminAction.CREATE);
        
        return adminNotificationRepository.save(notification);
    }
    
    public Page<AdminNotification> getAllNotifications(Pageable pageable) {
        return adminNotificationRepository.findAllByOrderByTimestampDesc(pageable);
    }
    
    public List<AdminNotification> getRecentNotifications() {
        return adminNotificationRepository.findTop10ByOrderByTimestampDesc();
    }
    
    public Page<AdminNotification> getNotificationsByType(AdminAction type, Pageable pageable) {
        return adminNotificationRepository.findByTypeOrderByTimestampDesc(type, pageable);
    }
    
    public Page<AdminNotification> getNotificationsByUser(Long userId, Pageable pageable) {
        return adminNotificationRepository.findByUserIdOrderByTimestampDesc(userId, pageable);
    }
    
    public Page<AdminNotification> getNotificationsByJob(Long jobId, Pageable pageable) {
        return adminNotificationRepository.findByJobIdOrderByTimestampDesc(jobId, pageable);
    }
    
    public List<AdminNotification> getNotificationsByDateRange(LocalDateTime start, LocalDateTime end) {
        return adminNotificationRepository.findByTimestampBetweenOrderByTimestampDesc(start, end);
    }
    
    // New methods for read/unread notifications
    
    public List<AdminNotification> getUnreadNotifications() {
        return adminNotificationRepository.findByReadFalseOrderByTimestampDesc();
    }
    
    public Page<AdminNotification> getNotificationsByReadStatus(Boolean read, Pageable pageable) {
        return adminNotificationRepository.findByReadOrderByTimestampDesc(read, pageable);
    }
    
    public Long getUnreadCount() {
        return adminNotificationRepository.countByReadFalse();
    }
    
    @Transactional
    public void markAsRead(Long id) {
        adminNotificationRepository.markAsRead(id);
    }
    
    @Transactional
    public void markMultipleAsRead(List<Long> ids) {
        adminNotificationRepository.markMultipleAsRead(ids);
    }
    
    @Transactional
    public void markAllAsRead() {
        adminNotificationRepository.markAllAsRead();
    }
} 