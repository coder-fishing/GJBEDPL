package org.example.goodjobbackend.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
@Data
@NoArgsConstructor
@Entity
@Table(name = "employers")
public class Employer {

    @Id
    private Long id;

    @Version
    private Long version;

    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name = "user_id")
    @JsonBackReference(value = "user-employer")
    private User user;

    @OneToMany(mappedBy = "employer")
    @JsonManagedReference(value = "employer-jobs")
    private List<Job> jobs = new ArrayList<>();

    @OneToMany(mappedBy = "employer")
    @JsonManagedReference(value = "employer-applications")
    private List<JobApplication> applications = new ArrayList<>();

    @Column(nullable = false)
    private String companyName;

    @Column(length = 1000)
    private String companyDescription;

    @Column(length = 500)
    private String companyWebsite;

    @Column(length = 1000)
    private String companyLogo;

    @Column(nullable = false)
    private String companyAddress;

    private String companySize;

    private String industry;

    @Column(length = 500)
    private String taxCode;

    @Column(length = 20)
    private String contactPhone;

    @Lob
    @Column(columnDefinition = "TEXT")
    private String socialLinks;

    @Column(nullable = false)
    private boolean verified = false;

    private String verificationDocument;

    @Column(nullable = false)
    private boolean active = true;
}
