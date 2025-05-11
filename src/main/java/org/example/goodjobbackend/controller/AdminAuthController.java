package org.example.goodjobbackend.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.dto.AdminLoginRequest;
import org.example.goodjobbackend.dto.AdminRegistrationRequest;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.service.AdminAuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/admin/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AdminAuthController {

    private final AdminAuthService adminAuthService;

    @PostMapping("/login")
    public ResponseEntity<User> login(@Valid @RequestBody AdminLoginRequest request) {
        User admin = adminAuthService.login(request);
        return ResponseEntity.ok(admin);
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody AdminRegistrationRequest request) {
        String result = adminAuthService.register(request);
        return ResponseEntity.ok(result);
    }
    
    @PostMapping("/verify")
    public ResponseEntity<User> verifyAdmin(
            @RequestParam String email, 
            @RequestParam String verificationCode) {
        User admin = adminAuthService.verifyAndCreateAdmin(email, verificationCode);
        return ResponseEntity.ok(admin);
    }
    
    @GetMapping("/current")
    public ResponseEntity<User> getCurrentAdmin() {
        User admin = adminAuthService.getCurrentAdmin();
        return ResponseEntity.ok(admin);
    }
    
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout() {
        adminAuthService.logout();
        return ResponseEntity.ok(Map.of("message", "Đăng xuất thành công"));
    }
} 