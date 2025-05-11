package org.example.goodjobbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SavedJobDTO {
    private Long id;
    private Long jobId;
    private String title;
    private String companyName;
    private String location;
    private String jobType;
    private Double salaryMin;
    private Double salaryMax;
    private String salaryCurrency;
    private LocalDateTime savedAt;
    private String imageUrl;
    private LocalDateTime postedAt;
    private LocalDateTime expireAt;
} 