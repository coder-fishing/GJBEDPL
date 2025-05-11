package org.example.goodjobbackend.controller;

import org.example.goodjobbackend.dto.AdminNotificationDTO;
import org.example.goodjobbackend.model.AdminAction;
import org.example.goodjobbackend.model.AdminNotification;
import org.example.goodjobbackend.service.AdminNotificationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/notifications")
// @PreAuthorize("hasRole('ADMIN')")
public class AdminNotificationController {

    @Autowired
    private AdminNotificationService adminNotificationService;

    @GetMapping
    public ResponseEntity<Page<AdminNotificationDTO>> getAllNotifications(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Page<AdminNotification> notificationPage = adminNotificationService.getAllNotifications(PageRequest.of(page, size));
        List<AdminNotificationDTO> dtoList = notificationPage.getContent().stream()
                .map(AdminNotificationDTO::fromEntity)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(new PageImpl<>(dtoList, notificationPage.getPageable(), notificationPage.getTotalElements()));
    }

    @GetMapping("/recent")
    public ResponseEntity<List<AdminNotificationDTO>> getRecentNotifications() {
        List<AdminNotification> notifications = adminNotificationService.getRecentNotifications();
        List<AdminNotificationDTO> dtoList = notifications.stream()
                .map(AdminNotificationDTO::fromEntity)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(dtoList);
    }

    @GetMapping("/byType")
    public ResponseEntity<Page<AdminNotificationDTO>> getNotificationsByType(
            @RequestParam AdminAction type,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Page<AdminNotification> notificationPage = adminNotificationService.getNotificationsByType(type, PageRequest.of(page, size));
        List<AdminNotificationDTO> dtoList = notificationPage.getContent().stream()
                .map(AdminNotificationDTO::fromEntity)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(new PageImpl<>(dtoList, notificationPage.getPageable(), notificationPage.getTotalElements()));
    }

    @GetMapping("/byUser/{userId}")
    public ResponseEntity<Page<AdminNotificationDTO>> getNotificationsByUser(
            @PathVariable Long userId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Page<AdminNotification> notificationPage = adminNotificationService.getNotificationsByUser(userId, PageRequest.of(page, size));
        List<AdminNotificationDTO> dtoList = notificationPage.getContent().stream()
                .map(AdminNotificationDTO::fromEntity)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(new PageImpl<>(dtoList, notificationPage.getPageable(), notificationPage.getTotalElements()));
    }

    @GetMapping("/byJob/{jobId}")
    public ResponseEntity<Page<AdminNotificationDTO>> getNotificationsByJob(
            @PathVariable Long jobId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Page<AdminNotification> notificationPage = adminNotificationService.getNotificationsByJob(jobId, PageRequest.of(page, size));
        List<AdminNotificationDTO> dtoList = notificationPage.getContent().stream()
                .map(AdminNotificationDTO::fromEntity)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(new PageImpl<>(dtoList, notificationPage.getPageable(), notificationPage.getTotalElements()));
    }

    @GetMapping("/byDateRange")
    public ResponseEntity<List<AdminNotificationDTO>> getNotificationsByDateRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {
        List<AdminNotification> notifications = adminNotificationService.getNotificationsByDateRange(start, end);
        List<AdminNotificationDTO> dtoList = notifications.stream()
                .map(AdminNotificationDTO::fromEntity)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(dtoList);
    }
    
    // New endpoints for read/unread notifications
    
    @GetMapping("/unread")
    public ResponseEntity<List<AdminNotificationDTO>> getUnreadNotifications() {
        List<AdminNotification> notifications = adminNotificationService.getUnreadNotifications();
        List<AdminNotificationDTO> dtoList = notifications.stream()
                .map(AdminNotificationDTO::fromEntity)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(dtoList);
    }
    
    @GetMapping("/byReadStatus")
    public ResponseEntity<Page<AdminNotificationDTO>> getNotificationsByReadStatus(
            @RequestParam Boolean read,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Page<AdminNotification> notificationPage = 
                adminNotificationService.getNotificationsByReadStatus(read, PageRequest.of(page, size));
        List<AdminNotificationDTO> dtoList = notificationPage.getContent().stream()
                .map(AdminNotificationDTO::fromEntity)
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(new PageImpl<>(dtoList, notificationPage.getPageable(), notificationPage.getTotalElements()));
    }
    
    @GetMapping("/unread/count")
    public ResponseEntity<Map<String, Long>> getUnreadCount() {
        Long count = adminNotificationService.getUnreadCount();
        return ResponseEntity.ok(Map.of("count", count));
    }
    
    @PutMapping("/{id}/read")
    public ResponseEntity<Void> markAsRead(@PathVariable Long id) {
        adminNotificationService.markAsRead(id);
        return ResponseEntity.ok().build();
    }
    
    @PutMapping("/read")
    public ResponseEntity<Void> markMultipleAsRead(@RequestBody List<Long> ids) {
        adminNotificationService.markMultipleAsRead(ids);
        return ResponseEntity.ok().build();
    }
    
    @PutMapping("/read/all")
    public ResponseEntity<Void> markAllAsRead() {
        adminNotificationService.markAllAsRead();
        return ResponseEntity.ok().build();
    }
} 