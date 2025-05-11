package org.example.goodjobbackend.controller;

import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.dto.AdminLoginRequest;
import org.example.goodjobbackend.dto.AdminRegistrationRequest;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.UserRole;
import org.example.goodjobbackend.service.AdminAuthService;
import org.example.goodjobbackend.service.TestDataService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/test/admin")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AdminTestController {

    private final AdminAuthService adminAuthService;
    private final TestDataService testDataService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register/mock")
    public ResponseEntity<Map<String, String>> createMockAdminRegistration() {
        AdminRegistrationRequest request = new AdminRegistrationRequest(
                "admin_test",
                "admin@example.com",
                "Test Admin",
                "Admin123@",
                "admin123" // Default admin code
        );
        
        try {
            String result = adminAuthService.register(request);
            return ResponseEntity.ok(Map.of(
                    "message", "Đăng ký admin thành công. Hãy kiểm tra email của bạn.",
                    "email", request.getEmail(),
                    "verificationCode", "123456" // Test verification code
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/verify/mock")
    public ResponseEntity<User> mockVerifyAdmin() {
        User admin = testDataService.getMockAdminUser();
        return ResponseEntity.ok(admin);
    }
    
    @PostMapping("/login/mock")
    public ResponseEntity<User> mockLoginAdmin(@RequestBody AdminLoginRequest request) {
        // For testing without requiring email verification
        User admin = testDataService.getMockAdminUser();
        
        // Only for test environment
        if ("admin@example.com".equals(request.getEmail()) && 
                "Admin123@".equals(request.getPassword())) {
            return ResponseEntity.ok(admin);
        }
        
        return ResponseEntity.badRequest().body(null);
    }
    
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getAdminTestStatus() {
        return ResponseEntity.ok(Map.of(
                "status", "SUCCESS",
                "message", "Admin API is working properly",
                "timestamp", System.currentTimeMillis()
        ));
    }
} 