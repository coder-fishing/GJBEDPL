package org.example.goodjobbackend.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "job_applications")
public class JobApplication {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "job_id", nullable = false)
    @JsonBackReference(value = "job-applications")
    private Job job;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "applicant_id", nullable = false)
    @JsonBackReference(value = "user-applications")
    private User applicant;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "employer_id", nullable = false)
    @JsonBackReference(value = "employer-applications")
    private Employer employer;

    @Column(columnDefinition = "TEXT")
    private String coverLetter;

    @Column(name = "resume_url")
    private String resumeUrl;

    @Column(name = "applied_at")
    private LocalDateTime appliedAt;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ApplicationStatus status = ApplicationStatus.PENDING;

    @Column(name = "employer_viewed")
    private boolean employerViewed = false;

    @PrePersist
    protected void onCreate() {
        appliedAt = LocalDateTime.now();
    }
} 