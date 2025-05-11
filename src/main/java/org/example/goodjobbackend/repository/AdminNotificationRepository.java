package org.example.goodjobbackend.repository;

import org.example.goodjobbackend.model.AdminAction;
import org.example.goodjobbackend.model.AdminNotification;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AdminNotificationRepository extends JpaRepository<AdminNotification, Long> {
    Page<AdminNotification> findAllByOrderByTimestampDesc(Pageable pageable);
    
    List<AdminNotification> findTop10ByOrderByTimestampDesc();
    
    Page<AdminNotification> findByTypeOrderByTimestampDesc(AdminAction type, Pageable pageable);
    
    Page<AdminNotification> findByUserIdOrderByTimestampDesc(Long userId, Pageable pageable);
    
    Page<AdminNotification> findByJobIdOrderByTimestampDesc(Long jobId, Pageable pageable);
    
    List<AdminNotification> findByTimestampBetweenOrderByTimestampDesc(LocalDateTime start, LocalDateTime end);
    
    // New methods for read/unread notifications
    List<AdminNotification> findByReadFalseOrderByTimestampDesc();
    
    Page<AdminNotification> findByReadOrderByTimestampDesc(Boolean read, Pageable pageable);
    
    Long countByReadFalse();
    
    @Modifying
    @Query("UPDATE AdminNotification a SET a.read = true WHERE a.id = :id")
    void markAsRead(@Param("id") Long id);
    
    @Modifying
    @Query("UPDATE AdminNotification a SET a.read = true WHERE a.id IN :ids")
    void markMultipleAsRead(@Param("ids") List<Long> ids);
    
    @Modifying
    @Query("UPDATE AdminNotification a SET a.read = true WHERE a.read = false")
    void markAllAsRead();
} 