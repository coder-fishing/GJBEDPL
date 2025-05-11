package org.example.goodjobbackend.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "jobs")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Job {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long jobId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "employer_id", insertable = false, updatable = false)
    @JsonBackReference(value = "employer-jobs")
    private Employer employer;

    @Column(name = "employer_id", nullable = false)
    private Long employerId;

    @OneToMany(mappedBy = "job", cascade = CascadeType.ALL)
    @JsonManagedReference(value = "job-applications")
    private List<JobApplication> applications = new ArrayList<>();

    @OneToMany(mappedBy = "job", cascade = CascadeType.ALL)
    @JsonManagedReference(value = "job-saved-by")
    private List<SavedJob> savedBy = new ArrayList<>();

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(columnDefinition = "TEXT")
    private String requirement;

    private String location;

    @Enumerated(EnumType.STRING)
    @Column(name = "job_type")
    private JobType jobType;

    @Column(name = "salary_min")
    private Double salaryMin;

    @Column(name = "salary_max")
    private Double salaryMax;

    @Column(name = "salary_currency")
    private String salaryCurrency;

    @Column(name = "apply_count")
    private Integer applyCount = 0;

    @Column(name = "view_count")
    private Integer viewCount = 0;

    @Column(name = "posted_at")
    private LocalDateTime postedAt;

    @Column(name = "expire_at")
    private LocalDateTime expireAt;

    @Column(name = "is_salary_public")
    private Boolean isSalaryPublic = false;

    @Column(name = "is_active")
    private Boolean isActive = true;

    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private JobStatus status = JobStatus.PENDING;

    @Column(name = "rejection_reason", columnDefinition = "TEXT")
    private String rejectionReason;

    @Column(name = "image_url")
    private String imageUrl;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "processed_by")
    @JsonBackReference(value = "user-processed-jobs")
    private User processedBy;

    @Column(name = "processed_at")
    private LocalDateTime processedAt;

    @PrePersist
    protected void onCreate() {
        postedAt = LocalDateTime.now();
        if (expireAt == null) {
            expireAt = postedAt.plusDays(30); // Default expiry of 30 days
        }
        status = JobStatus.PENDING;
    }
}