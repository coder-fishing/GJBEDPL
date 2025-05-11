package org.example.goodjobbackend.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.dto.*;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.service.AuthService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest request) {
        String result = authService.register(request);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/verify")
    public ResponseEntity<User> verifyEmail(@Valid @RequestBody VerifyRequest request) {
        User user = authService.verifyAndCreateUser(request.getEmail(), request.getVerificationCode());
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<String> resendVerificationCode(@RequestParam String email) {
        authService.resendVerificationCode(email);
        return ResponseEntity.ok("Mã xác thực đã được gửi lại");
    }

    @PostMapping("/reset-password/request")
    public ResponseEntity<String> requestPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        String result = authService.requestPasswordReset(request.getEmail());
        return ResponseEntity.ok(result);
    }

    @PostMapping("/reset-password/verify")
    public ResponseEntity<String> verifyAndResetPassword(@Valid @RequestBody PasswordResetRequest request) {
        if (request.getVerificationCode() == null || request.getNewPassword() == null) {
            return ResponseEntity.badRequest().body("Vui lòng cung cấp mã xác thực và mật khẩu mới");
        }
        authService.verifyAndResetPassword(request.getEmail(), request.getVerificationCode(), request.getNewPassword());
        return ResponseEntity.ok("Mật khẩu đã được đặt lại thành công");
    }

    @PostMapping("/reset-password/resend")
    public ResponseEntity<String> resendPasswordResetCode(@RequestParam String email) {
        authService.resendPasswordResetCode(email);
        return ResponseEntity.ok("Mã xác thực đã được gửi lại");
    }

    @PostMapping("/otp/resend")
    public ResponseEntity<String> resendPendingVerificationCode(@Valid @RequestBody EmailRequest request) {
        authService.resendPendingVerificationCode(request.getEmail());
        return ResponseEntity.ok("Mã xác thực đã được gửi lại");
    }
}