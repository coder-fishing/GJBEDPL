package org.example.goodjobbackend.service;

import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.goodjobbackend.dto.LoginRequest;
import org.example.goodjobbackend.dto.RegisterRequest;
import org.example.goodjobbackend.model.Employer;
import org.example.goodjobbackend.model.PendingRegistration;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.UserRole;
import org.example.goodjobbackend.repository.EmployerRepository;
import org.example.goodjobbackend.repository.PendingRegistrationRepository;
import org.example.goodjobbackend.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PendingRegistrationRepository pendingRegistrationRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final EmployerRepository employerRepository;

    @Transactional
    public String register(RegisterRequest request) {
        // Kiểm tra username đã tồn tại chưa
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username đã tồn tại");
        }

        // Kiểm tra email đã tồn tại trong bảng users
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email đã tồn tại");
        }

        // Kiểm tra và xử lý đăng ký tạm thời
        Optional<PendingRegistration> existingRegistration = pendingRegistrationRepository.findByEmail(request.getEmail());
        if (existingRegistration.isPresent()) {
            PendingRegistration registration = existingRegistration.get();
            // Nếu đã được sử dụng hoặc hết hạn, cho phép ghi đè
            if (!registration.isUsed() || registration.isExpired()) {
                // Cập nhật thông tin mới cho bản ghi cũ
                registration.setUsername(request.getUsername());
                registration.setPassword(passwordEncoder.encode(request.getPassword()));
                registration.setFullName(request.getFullName());
                registration.setRole(request.getRole());
                registration.setVerificationCode(registration.generateVerificationCode());
                registration.setExpiryDate(registration.generateExpiryDate());
                registration.setUsed(false);
                
                registration = pendingRegistrationRepository.save(registration);
                
                // Gửi email xác thực
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

        // Tạo đăng ký tạm thời mới nếu chưa tồn tại
        PendingRegistration registration = new PendingRegistration(
            request.getUsername(),
            passwordEncoder.encode(request.getPassword()),
            request.getFullName(),
            request.getEmail(),
            request.getRole()
        );

        registration = pendingRegistrationRepository.save(registration);

        // Gửi email xác thực
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
    public User verifyAndCreateUser(String email, String verificationCode) {
        PendingRegistration registration = pendingRegistrationRepository
                .findByEmailAndVerificationCodeAndUsedFalse(email, verificationCode)
                .orElseThrow(() -> new RuntimeException("Mã xác thực không hợp lệ"));

        if (registration.isExpired()) {
            throw new RuntimeException("Mã xác thực đã hết hạn");
        }

        // Tạo user mới
        User user = new User();
        user.setUsername(registration.getUsername());
        user.setPassword(registration.getPassword()); // Đã được mã hóa
        user.setFullName(registration.getFullName());
        user.setEmail(registration.getEmail());
        user.setRole(registration.getRole());
        user.setEnabled(true);

        // Lưu user và đánh dấu đăng ký tạm thời đã sử dụng
        registration.setUsed(true);
        pendingRegistrationRepository.save(registration);
        return userRepository.save(user);
    }

    private void createEmployerProfile(User user) {
        Employer employer = new Employer();
        employer.setId(user.getId());
        employer.setUser(user);
        employer.setActive(true);
        employer.setVerified(false);
        employerRepository.save(employer);
    }

    public User login(LoginRequest request) {
        return userRepository.findByUsername(request.getUsername())
                .filter(user -> passwordEncoder.matches(request.getPassword(), user.getPassword()))
                .filter(User::isEnabled)
                .orElseThrow(() -> new RuntimeException("Username hoặc password không đúng"));
    }

    @Transactional
    public void resendVerificationCode(String email) {
        PendingRegistration registration = pendingRegistrationRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy yêu cầu đăng ký cho email này"));

        if (registration.isExpired()) {
            // Tạo mã xác thực mới
            registration = new PendingRegistration(
                registration.getUsername(),
                registration.getPassword(),
                registration.getFullName(),
                registration.getEmail(),
                registration.getRole()
            );
            registration = pendingRegistrationRepository.save(registration);
        }

        try {
            emailService.sendVerificationCode(
                registration.getEmail(),
                registration.getVerificationCode(),
                registration.getFullName()
            );
        } catch (MessagingException e) {
            throw new RuntimeException("Không thể gửi lại mã xác thực");
        }
    }

    @Transactional
    public String requestPasswordReset(String email) {
        log.info("Yêu cầu đặt lại mật khẩu cho email: {}", email);
        
        // Kiểm tra email có tồn tại không
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Email không tồn tại trong hệ thống"));

        // Tạo hoặc cập nhật yêu cầu đặt lại mật khẩu
        PendingRegistration resetRequest = pendingRegistrationRepository.findByEmail(email)
                .map(existing -> {
                    // Cập nhật thông tin cho yêu cầu hiện có
                    existing.setVerificationCode(existing.generateVerificationCode());
                    existing.setExpiryDate(existing.generateExpiryDate());
                    existing.setUsed(false);
                    return existing;
                })
                .orElseGet(() -> new PendingRegistration(
                    user.getUsername(),
                    user.getPassword(),
                    user.getFullName(),
                    email,
                    user.getRole()
                ));

        resetRequest = pendingRegistrationRepository.save(resetRequest);
        log.info("Đã tạo/cập nhật yêu cầu đặt lại mật khẩu với mã: {}", resetRequest.getVerificationCode());

        // Gửi mã xác thực
        try {
            emailService.sendVerificationCode(
                email,
                resetRequest.getVerificationCode(),
                user.getFullName()
            );
            return "Mã xác thực đã được gửi đến email của bạn";
        } catch (MessagingException e) {
            log.error("Lỗi khi gửi email: {}", e.getMessage());
            throw new RuntimeException("Không thể gửi email xác thực");
        }
    }

    @Transactional
    public void verifyAndResetPassword(String email, String verificationCode, String newPassword) {
        log.info("Xác thực và đặt lại mật khẩu cho email: {}", email);
        
        // Tìm yêu cầu đặt lại mật khẩu
        PendingRegistration resetRequest = pendingRegistrationRepository
                .findByEmailAndVerificationCodeAndUsedFalse(email, verificationCode)
                .orElseThrow(() -> {
                    log.error("Không tìm thấy yêu cầu hợp lệ cho email: {}", email);
                    return new RuntimeException("Mã xác thực không hợp lệ");
                });

        if (resetRequest.isExpired()) {
            log.error("Mã xác thực đã hết hạn cho email: {}", email);
            throw new RuntimeException("Mã xác thực đã hết hạn");
        }

        // Cập nhật mật khẩu mới
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy tài khoản"));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        log.info("Đã cập nhật mật khẩu mới cho user: {}", user.getUsername());

        // Đánh dấu yêu cầu đã sử dụng
        resetRequest.setUsed(true);
        pendingRegistrationRepository.save(resetRequest);
    }

    @Transactional
    public void resendPasswordResetCode(String email) {
        log.info("Gửi lại mã đặt lại mật khẩu cho email: {}", email);
        
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Email không tồn tại trong hệ thống"));

        // Tạo hoặc cập nhật yêu cầu đặt lại mật khẩu
        PendingRegistration resetRequest = pendingRegistrationRepository.findByEmail(email)
                .map(existing -> {
                    // Cập nhật thông tin cho yêu cầu hiện có
                    existing.setVerificationCode(existing.generateVerificationCode());
                    existing.setExpiryDate(existing.generateExpiryDate());
                    existing.setUsed(false);
                    return existing;
                })
                .orElseGet(() -> new PendingRegistration(
                    user.getUsername(),
                    user.getPassword(),
                    user.getFullName(),
                    email,
                    user.getRole()
                ));

        resetRequest = pendingRegistrationRepository.save(resetRequest);

        try {
            emailService.sendVerificationCode(
                email,
                resetRequest.getVerificationCode(),
                user.getFullName()
            );
            log.info("Đã gửi lại mã xác thực thành công");
        } catch (MessagingException e) {
            log.error("Lỗi khi gửi lại mã xác thực: {}", e.getMessage());
            throw new RuntimeException("Không thể gửi lại mã xác thực");
        }
    }

    @Transactional
    public void resendPendingVerificationCode(String email) {
        log.info("Gửi lại mã xác thực cho email trong pending: {}", email);

        // Tìm bản ghi pending theo email
        PendingRegistration pending = pendingRegistrationRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Email chưa đăng ký yêu cầu xác thực"));

        // Cập nhật mã xác thực và hạn
        pending.setVerificationCode(pending.generateVerificationCode());
        pending.setExpiryDate(pending.generateExpiryDate());
        pending.setUsed(false);

        pending = pendingRegistrationRepository.save(pending);

        try {
            emailService.sendVerificationCode(
                    email,
                    pending.getVerificationCode(),
                    pending.getFullName() // Lấy tên từ pending
            );
            log.info("Đã gửi lại mã xác thực thành công cho email pending");
        } catch (MessagingException e) {
            log.error("Lỗi khi gửi mã xác thực: {}", e.getMessage());
            throw new RuntimeException("Không thể gửi lại mã xác thực");
        }
    }

} 