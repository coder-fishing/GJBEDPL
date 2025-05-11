package org.example.goodjobbackend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@Entity
@Table(name = "users")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = true)  // Password có thể null với tài khoản Google
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "avatar_url", length = 2000)
    private String avatarUrl;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "bio", length = 1000)
    private String bio;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role = UserRole.USER;

    @Column(nullable = false)
    private boolean active = true;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonIgnoreProperties(value = {"user", "hibernateLazyInitializer", "handler"})
    private Employer employerProfile;

    @OneToMany(mappedBy = "applicant", cascade = CascadeType.ALL)
    @JsonManagedReference(value = "user-applications")
    private List<JobApplication> applications = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonManagedReference(value = "user-notifications")
    private List<Notification> notifications = new ArrayList<>();

    @OneToMany(mappedBy = "processedBy")
    @JsonManagedReference(value = "user-processed-jobs")
    private List<Job> processedJobs = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonManagedReference(value = "user-admin-actions")
    private List<AdminNotification> adminNotifications = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonManagedReference(value = "user-saved-jobs")
    private List<SavedJob> savedJobs = new ArrayList<>();

    // Thông tin cho OAuth2 (Google login)
    @Column(name = "oauth2_provider")
    private String provider;  // "google", "facebook", etc.

    @Column(name = "oauth2_id")
    private String providerId;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    private boolean isEnabled = false;

    // Kiểm tra xem user có phải là OAuth2 user không
    public boolean isOAuth2User() {
        return provider != null && providerId != null;
    }

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        lastLogin = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        lastLogin = LocalDateTime.now();
    }
}
