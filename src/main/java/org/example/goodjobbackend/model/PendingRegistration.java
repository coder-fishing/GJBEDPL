package org.example.goodjobbackend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@Entity
@Table(name = "pending_registrations")
public class PendingRegistration {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String fullName;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String verificationCode;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role = UserRole.USER;

    private boolean used;

    public PendingRegistration(String username, String password, String fullName, String email, UserRole role) {
        this.username = username;
        this.password = password;
        this.fullName = fullName;
        this.email = email;
        this.role = role;
        this.verificationCode = generateVerificationCode();
        this.expiryDate = generateExpiryDate();
        this.used = false;
    }

    public String generateVerificationCode() {
        // Tạo mã xác thực 6 số
        int code = 1000 + (int)(Math.random() * 9000);
        return String.valueOf(code);
    }

    public LocalDateTime generateExpiryDate() {
        return LocalDateTime.now().plusMinutes(15); // Hết hạn sau 15 phút
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }
} 