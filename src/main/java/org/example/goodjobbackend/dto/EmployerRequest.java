package org.example.goodjobbackend.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class EmployerRequest {
    @NotBlank(message = "Tên công ty không được để trống")
    private String companyName;

    private String companyDescription;

    private String companyWebsite;

    private String companyLogo;

    @NotBlank(message = "Địa chỉ công ty không được để trống")
    private String companyAddress;

    private String companySize;

    private String industry;

    private String taxCode;

    private String contactPhone;

    private String socialLinks;

    private String verificationDocument;
} 