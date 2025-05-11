package org.example.goodjobbackend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class EmployerUpdateRequest {
    @NotBlank(message = "Tên công ty không được để trống")
    private String companyName;

    @Size(max = 1000, message = "Mô tả công ty không được vượt quá 1000 ký tự")
    private String companyDescription;

    @Size(max = 500, message = "Website công ty không được vượt quá 500 ký tự")
    private String companyWebsite;

    @Size(max = 1000, message = "URL logo không được vượt quá 1000 ký tự")
    private String companyLogo;

    @NotBlank(message = "Địa chỉ công ty không được để trống")
    private String companyAddress;

    private String companySize;

    private String industry;

    @Size(max = 500, message = "Mã số thuế không được vượt quá 500 ký tự")
    private String taxCode;

    @Size(max = 20, message = "Số điện thoại không được vượt quá 20 ký tự")
    private String contactPhone;

    private String socialLinks;
} 