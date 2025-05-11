package org.example.goodjobbackend.dto;

import lombok.Data;
import org.example.goodjobbackend.model.JobType;
import org.example.goodjobbackend.model.JobStatus;

import java.time.LocalDateTime;

@Data
public class JobRequest {
    private Long employerId;
    private String title;
    private String description;
    private String requirement;
    private String location;
    private JobType jobType;
    private Double salaryMin;
    private Double salaryMax;
    private String salaryCurrency;
    private LocalDateTime expireAt;
    private Boolean isSalaryPublic;
    private String imageUrl;
}