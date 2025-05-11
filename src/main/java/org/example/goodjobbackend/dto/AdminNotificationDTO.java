package org.example.goodjobbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.goodjobbackend.model.AdminAction;
import org.example.goodjobbackend.model.AdminNotification;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdminNotificationDTO {
    private Long id;
    private AdminAction type;
    private Long jobId;
    private String jobTitle;
    private LocalDateTime timestamp;
    private String username;
    private String description;
    private Boolean read;
    
    public static AdminNotificationDTO fromEntity(AdminNotification entity) {
        AdminNotificationDTO dto = new AdminNotificationDTO();
        dto.setId(entity.getId());
        dto.setType(entity.getType());
        dto.setJobId(entity.getJobId());
        dto.setJobTitle(entity.getJobTitle());
        dto.setTimestamp(entity.getTimestamp());
        dto.setUsername(entity.getUsername());
        dto.setDescription(entity.getDescription());
        dto.setRead(entity.getRead());
        return dto;
    }
} 