package org.example.goodjobbackend.service;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.goodjobbackend.dto.AdminLoginRequest;
import org.example.goodjobbackend.dto.AdminRegistrationRequest;
import org.example.goodjobbackend.model.PendingRegistration;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.UserRole;
import org.example.goodjobbackend.repository.PendingRegistrationRepository;
import org.example.goodjobbackend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminAuthService {

    private final UserRepository userRepository;
    private final PendingRegistrationRepository pendingRegistrationRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Value("${admin.registration.code:admin123}")
    private String adminRegistrationCode;

    @Transactional
    public String register(AdminRegistrationRequest request) {
        // Verify admin code
        if (!adminRegistrationCode.equals(request.getAdminCode())) {
            throw new RuntimeException("Mã admin không hợp lệ");
        }

        // Check if username already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username đã tồn tại");
        }

        // Check if email already exists in users table
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email đã tồn tại");
        }

        // Check for existing pending registrations
        Optional<PendingRegistration> existingRegistration = pendingRegistrationRepository.findByEmail(request.getEmail());
        if (existingRegistration.isPresent()) {
            PendingRegistration registration = existingRegistration.get();
            // Allow override if already used or expired
            if (!registration.isUsed() || registration.isExpired()) {
                // Update info for the existing record
                registration.setUsername(request.getUsername());
                registration.setPassword(passwordEncoder.encode(request.getPassword()));
                registration.setFullName(request.getFullName());
                registration.setRole(UserRole.ADMIN); // Force ADMIN role
                registration.setVerificationCode(registration.generateVerificationCode());
                registration.setExpiryDate(registration.generateExpiryDate());
                registration.setUsed(false);
                
                registration = pendingRegistrationRepository.save(registration);
                
                // Send verification email
                try {
                    emailService.sendVerificationCode(
                        registration.getEmail(),
                        registration.getVerificationCode(),
                        registration.getFullName()
                    );
                    return "Mã xác thực đã được gửi đến email của bạn";
                } catch (MessagingException e) {
                    throw new RuntimeException("Không thể gửi email xác thực");
                }
            } else {
                throw new RuntimeException("Email này đã đăng ký và đang chờ xác thực. Vui lòng kiểm tra email hoặc yêu cầu gửi lại mã xác thực.");
            }
        }

        // Create new pending registration
        PendingRegistration registration = new PendingRegistration(
            request.getUsername(),
            passwordEncoder.encode(request.getPassword()),
            request.getFullName(),
            request.getEmail(),
            UserRole.ADMIN // Force ADMIN role
        );

        registration = pendingRegistrationRepository.save(registration);

        // Send verification email
        try {
            emailService.sendVerificationCode(
                registration.getEmail(),
                registration.getVerificationCode(),
                registration.getFullName()
            );
            return "Mã xác thực đã được gửi đến email của bạn";
        } catch (MessagingException e) {
            pendingRegistrationRepository.delete(registration);
            throw new RuntimeException("Không thể gửi email xác thực");
        }
    }

    @Transactional
    public User verifyAndCreateAdmin(String email, String verificationCode) {
        PendingRegistration registration = pendingRegistrationRepository
                .findByEmailAndVerificationCodeAndUsedFalse(email, verificationCode)
                .orElseThrow(() -> new RuntimeException("Mã xác thực không hợp lệ"));

        if (registration.isExpired()) {
            throw new RuntimeException("Mã xác thực đã hết hạn");
        }

        // Verify that the role is ADMIN
        if (registration.getRole() != UserRole.ADMIN) {
            throw new RuntimeException("Đăng ký này không phải cho người dùng admin");
        }

        // Create new admin user
        User admin = new User();
        admin.setUsername(registration.getUsername());
        admin.setPassword(registration.getPassword()); // Already encrypted
        admin.setFullName(registration.getFullName());
        admin.setEmail(registration.getEmail());
        admin.setRole(UserRole.ADMIN);
        admin.setEnabled(true);

        // Save user and mark registration as used
        registration.setUsed(true);
        pendingRegistrationRepository.save(registration);
        return userRepository.save(admin);
    }

    public User login(AdminLoginRequest request) {
        User admin = userRepository.findByEmail(request.getEmail())
                .filter(user -> user.getRole() == UserRole.ADMIN)
                .filter(user -> passwordEncoder.matches(request.getPassword(), user.getPassword()))
                .filter(User::isEnabled)
                .orElseThrow(() -> new RuntimeException("Email hoặc mật khẩu không đúng, hoặc tài khoản không phải admin"));

        // Store the admin in the session
        HttpServletRequest servletRequest = 
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        HttpSession session = servletRequest.getSession(true);
        session.setAttribute("currentAdmin", admin);
        
        return admin;
    }

    public User getCurrentAdmin() {
        // Get from session if available
        HttpServletRequest servletRequest = 
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        HttpSession session = servletRequest.getSession(false);
        
        if (session != null) {
            User admin = (User) session.getAttribute("currentAdmin");
            if (admin != null) {
                // Refresh from database to ensure we have the latest data
                return userRepository.findById(admin.getId())
                        .filter(user -> user.getRole() == UserRole.ADMIN)
                        .orElseThrow(() -> new UsernameNotFoundException("Admin not found"));
            }
        }
        
        // Otherwise, get from security context
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        if (username != null && !username.equals("anonymousUser")) {
            return userRepository.findByUsername(username)
                    .filter(user -> user.getRole() == UserRole.ADMIN)
                    .orElseThrow(() -> new UsernameNotFoundException("Admin not found"));
        }
        
        throw new RuntimeException("Không tìm thấy thông tin đăng nhập");
    }
    
    public void logout() {
        // Clear session
        HttpServletRequest servletRequest = 
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        HttpSession session = servletRequest.getSession(false);
        if (session != null) {
            session.removeAttribute("currentAdmin");
            session.invalidate();
        }
        
        // Clear security context
        SecurityContextHolder.clearContext();
    }
} 