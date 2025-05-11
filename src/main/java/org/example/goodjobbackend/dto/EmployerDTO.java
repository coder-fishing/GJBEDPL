package org.example.goodjobbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.goodjobbackend.model.Employer;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmployerDTO {
    private Long id;
    private Long userId;
    private String companyName;
    private String companyDescription;
    private String companyWebsite;
    private String companyLogo;
    private String companyAddress;
    private String companySize;
    private String industry;
    private String taxCode;
    private String contactPhone;
    private String socialLinks;
    private boolean verified;
    private boolean active;
    private String verificationDocument;

    public static EmployerDTO fromEntity(Employer employer) {
        return EmployerDTO.builder()
                .id(employer.getId())
                .userId(employer.getUser().getId())
                .companyName(employer.getCompanyName())
                .companyDescription(employer.getCompanyDescription())
                .companyWebsite(employer.getCompanyWebsite())
                .companyLogo(employer.getCompanyLogo())
                .companyAddress(employer.getCompanyAddress())
                .companySize(employer.getCompanySize())
                .industry(employer.getIndustry())
                .taxCode(employer.getTaxCode())
                .contactPhone(employer.getContactPhone())
                .socialLinks(employer.getSocialLinks())
                .verified(employer.isVerified())
                .active(employer.isActive())
                .verificationDocument(employer.getVerificationDocument())
                .build();
    }
}