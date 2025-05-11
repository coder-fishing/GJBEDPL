package org.example.goodjobbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.goodjobbackend.model.ApplicationStatus;
import org.example.goodjobbackend.model.JobType;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JobApplicationDTO {
    private Long id;
    private Long jobId;
    private String jobTitle;
    private Long applicantId;
    private String applicantName;
    private String applicantEmail;
    private Long employerId;
    private String employerName;
    private String coverLetter;
    private String resumeUrl;
    private LocalDateTime appliedAt;
    private ApplicationStatus status;
    private boolean employerViewed;
    private String imageUrl;
    private JobType jobType;
} 