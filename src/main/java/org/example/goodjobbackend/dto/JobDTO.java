package org.example.goodjobbackend.dto;

import lombok.Data;
import org.example.goodjobbackend.model.Job;
import org.example.goodjobbackend.model.JobStatus;
import org.example.goodjobbackend.model.JobType;
import java.time.LocalDateTime;

@Data
public class JobDTO {
    private Long jobId;
    private Long employerId;
    private String employerName;
    private String companyLogo;
    private String title;
    private String description;
    private String requirement;
    private String location;
    private JobType jobType;
    private Double salaryMin;
    private Double salaryMax;
    private String salaryCurrency;
    private Integer applyCount;
    private Integer viewCount;
    private LocalDateTime postedAt;
    private LocalDateTime expireAt;
    private Boolean isSalaryPublic;
    private Boolean isActive;
    private JobStatus status;
    private String imageUrl;

    public static JobDTO fromEntity(Job job) {
        JobDTO dto = new JobDTO();
        dto.setJobId(job.getJobId());
        dto.setEmployerId(job.getEmployer().getId());
        dto.setEmployerName(job.getEmployer().getCompanyName());
        dto.setCompanyLogo(job.getEmployer().getCompanyLogo());
        dto.setTitle(job.getTitle());
        dto.setDescription(job.getDescription());
        dto.setRequirement(job.getRequirement());
        dto.setLocation(job.getLocation());
        dto.setJobType(job.getJobType());
        dto.setSalaryMin(job.getSalaryMin());
        dto.setSalaryMax(job.getSalaryMax());
        dto.setSalaryCurrency(job.getSalaryCurrency());
        dto.setApplyCount(job.getApplyCount());
        dto.setViewCount(job.getViewCount());
        dto.setPostedAt(job.getPostedAt());
        dto.setExpireAt(job.getExpireAt());
        dto.setIsSalaryPublic(job.getIsSalaryPublic());
        dto.setIsActive(job.getIsActive());
        dto.setStatus(job.getStatus());
        dto.setImageUrl(job.getImageUrl());
        return dto;
    }
} 