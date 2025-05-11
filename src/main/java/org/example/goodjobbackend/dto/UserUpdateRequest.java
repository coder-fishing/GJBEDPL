package org.example.goodjobbackend.dto;

import lombok.Data;
import jakarta.validation.constraints.Size;

@Data
public class UserUpdateRequest {
    @Size(min = 2, max = 100, message = "Full name must be between 2 and 100 characters")
    private String fullName;

    @Size(max = 15, message = "Phone number cannot exceed 15 characters")
    private String phoneNumber;

    @Size(max = 2000, message = "Avatar URL cannot exceed 2000 characters")
    private String avatarUrl;

    @Size(max = 1000, message = "Bio cannot exceed 1000 characters")
    private String bio;
} 