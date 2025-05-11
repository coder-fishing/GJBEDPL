package org.example.goodjobbackend.dto;

import lombok.Data;

@Data
public class JobApplicationRequest {
    private Long jobId;
    private Long applicantId;
    private String coverLetter;
    private String resumeUrl;
} 