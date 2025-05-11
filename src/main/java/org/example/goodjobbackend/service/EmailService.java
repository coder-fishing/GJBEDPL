package org.example.goodjobbackend.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.example.goodjobbackend.model.JobApplication;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.frontend-url:http://localhost:3000}")
    private String frontendUrl;

    public void sendVerificationEmail(String to, String token, String fullName) throws MessagingException {
        log.info("Bắt đầu gửi email xác thực đến: {}", to);
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            Context context = new Context();
            context.setVariable("verificationLink", frontendUrl + "/verify-email?token=" + token);
            context.setVariable("fullName", fullName);
            context.setVariable("expiryHours", 24);

            String htmlContent = templateEngine.process("verification-email", context);

            helper.setTo(to);
            helper.setFrom(fromEmail);
            helper.setSubject("Xác thực tài khoản - GoodJob");
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Đã gửi email xác thực thành công đến: {}", to);
        } catch (Exception e) {
            log.error("Lỗi khi gửi email xác thực đến {}: {}", to, e.getMessage(), e);
            throw e;
        }
    }

    public void sendOTPEmail(String to, String otp, String fullName) throws MessagingException {
        log.info("Bắt đầu gửi email OTP đến: {}", to);
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            Context context = new Context();
            context.setVariable("otp", otp);
            context.setVariable("fullName", fullName);
            context.setVariable("expiryMinutes", 5);

            String htmlContent = templateEngine.process("otp-email", context);

            helper.setTo(to);
            helper.setFrom(fromEmail);
            helper.setSubject("Mã xác thực OTP - GoodJob");
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Đã gửi email OTP thành công đến: {}", to);
        } catch (Exception e) {
            log.error("Lỗi khi gửi email OTP đến {}: {}", to, e.getMessage(), e);
            throw e;
        }
    }

    public void sendVerificationCode(String to, String code, String fullName) throws MessagingException {
        log.info("Bắt đầu gửi mã xác thực đến: {}", to);
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            Context context = new Context();
            context.setVariable("verificationCode", code);
            context.setVariable("fullName", fullName);
            context.setVariable("expiryMinutes", 15);

            String htmlContent = templateEngine.process("verification-code", context);

            helper.setTo(to);
            helper.setFrom(fromEmail);
            helper.setSubject("Mã xác thực đăng ký - GoodJob");
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Đã gửi mã xác thực thành công đến: {}", to);
        } catch (Exception e) {
            log.error("Lỗi khi gửi mã xác thực đến {}: {}", to, e.getMessage(), e);
            throw e;
        }
    }

    public void sendApplicationStatusEmail(JobApplication application) throws MessagingException {
        String templateName = "application-status";
        Context context = new Context();
        
        // Thêm các thông tin cần thiết vào context
        context.setVariable("applicantName", application.getApplicant().getFullName());
        context.setVariable("jobTitle", application.getJob().getTitle());
        context.setVariable("companyName", application.getEmployer().getCompanyName());
        context.setVariable("status", application.getStatus().name());
        context.setVariable("isApproved", application.getStatus().name().equals("APPROVED"));
        
        // Process template thành HTML
        String emailContent = templateEngine.process(templateName, context);

        // Tạo email message
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setTo(application.getApplicant().getEmail());
        helper.setSubject("Cập nhật trạng thái đơn ứng tuyển - " + application.getJob().getTitle());
        helper.setText(emailContent, true);

        // Gửi email
        mailSender.send(message);
    }
}