package org.example.goodjobbackend.dto;

import lombok.Data;
import org.example.goodjobbackend.model.JobStatus;

@Data
public class JobProcessRequest {
    private JobStatus status;
    private String rejectionReason;  // Chỉ cần khi status là REJECTED
    private Long adminId;            // ID của admin xử lý
} 