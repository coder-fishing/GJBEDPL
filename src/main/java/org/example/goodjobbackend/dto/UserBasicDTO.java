package org.example.goodjobbackend.dto;

import lombok.Data;
import org.example.goodjobbackend.model.UserRole;

@Data
public class UserBasicDTO {
    private Long id;
    private String username;
    private String fullName;
    private String email;
    private String phoneNumber;
    private String avatarUrl;
    private String bio;
    private UserRole role;
    private boolean active;
    private boolean enabled;
} 