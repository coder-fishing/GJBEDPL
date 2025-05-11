package org.example.goodjobbackend.service;

import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.UserRole;
import org.springframework.stereotype.Service;

@Service
public class TestDataService {
    
    /**
     * Returns a mock admin user for testing purposes
     * This avoids the need for authentication during API testing
     */
    public User getMockAdminUser() {
        User mockAdmin = new User();
        mockAdmin.setId(1L);
        mockAdmin.setUsername("admin@example.com");
        mockAdmin.setEmail("admin@example.com");
        mockAdmin.setFullName("Test Admin");
        mockAdmin.setRole(UserRole.ADMIN);
        mockAdmin.setActive(true);
        mockAdmin.setEnabled(true);
        return mockAdmin;
    }
    
    /**
     * Returns a mock employer user for testing purposes
     */
    public User getMockEmployerUser() {
        User mockEmployer = new User();
        mockEmployer.setId(2L);
        mockEmployer.setUsername("employer@example.com");
        mockEmployer.setEmail("employer@example.com");
        mockEmployer.setFullName("Test Employer");
        mockEmployer.setRole(UserRole.EMPLOYER);
        mockEmployer.setActive(true);
        mockEmployer.setEnabled(true);
        return mockEmployer;
    }
} 