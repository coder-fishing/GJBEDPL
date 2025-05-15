package org.example.goodjobbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class NotificationRequest {
    private String title;
    private String message;
    private String type;  // JOB_APPROVED, JOB_REJECTED, NEW_APPLICATION, etc.
    private Long jobId;   // Optional, for job-related notifications
}