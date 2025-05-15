package org.example.goodjobbackend.service;

import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.goodjobbackend.dto.JobApplicationDTO;
import org.example.goodjobbackend.dto.JobApplicationRequest;
import org.example.goodjobbackend.model.ApplicationStatus;
import org.example.goodjobbackend.model.JobApplication;
import org.example.goodjobbackend.model.NotificationType;
import org.example.goodjobbackend.repository.JobApplicationRepository;
import org.example.goodjobbackend.repository.JobRepository;
import org.example.goodjobbackend.repository.UserRepository;
import org.example.goodjobbackend.repository.EmployerRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class JobApplicationService {

    private final JobApplicationRepository jobApplicationRepository;
    private final EmailService emailService;
    private final JobRepository jobRepository;
    private final UserRepository userRepository;
    private final EmployerRepository employerRepository;
    private final NotificationService notificationService;

    /**
     * Nộp đơn ứng tuyển
     */
    @jakarta.transaction.Transactional
    public JobApplication apply(JobApplicationRequest request) {
        // Kiểm tra xem đã apply chưa
        List<JobApplication> existingApplications = jobApplicationRepository.findByJobIdAndApplicantId(
                request.getJobId(), request.getApplicantId());
        if (!existingApplications.isEmpty()) {
            throw new RuntimeException("Bạn đã ứng tuyển vị trí này rồi");
        }

        // Tìm job, user và employer
        var job = jobRepository.findById(request.getJobId())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy công việc với ID: " + request.getJobId()));
        
        var applicant = userRepository.findById(request.getApplicantId())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy người dùng với ID: " + request.getApplicantId()));
        
        var employer = employerRepository.findById(job.getEmployerId())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy nhà tuyển dụng với ID: " + job.getEmployerId()));

        // Tạo đơn ứng tuyển mới
        JobApplication application = JobApplication.builder()
                .job(job)
                .applicant(applicant)
                .employer(employer)
                .coverLetter(request.getCoverLetter())
                .resumeUrl(request.getResumeUrl())
                .status(ApplicationStatus.PENDING)
                .employerViewed(false)
                .build();

        // Lưu đơn ứng tuyển
        application = jobApplicationRepository.save(application);

        // Tăng số lượng ứng tuyển của job
        jobRepository.incrementApplyCount(request.getJobId());

        return application;
    }

    public List<JobApplicationDTO> getApplicationsByUserId(Long userId) {
        List<JobApplication> applications = jobApplicationRepository.findByApplicantId(userId);
        return applications.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    public List<JobApplicationDTO> getApplicationsByJobId(Long jobId) {
        List<JobApplication> applications = jobApplicationRepository.findByJobId(jobId);
        return applications.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    public List<JobApplicationDTO> getApplicationsByEmployerId(Long employerId) {
        List<JobApplication> applications = jobApplicationRepository.findByEmployerId(employerId);
        return applications.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Transactional
    public JobApplicationDTO updateApplicationStatus(Long applicationId, ApplicationStatus status) {
        if (status == null) {
            throw new IllegalArgumentException("Trạng thái không được để trống");
        }

        // Kiểm tra xem status có phải là một trong các giá trị hợp lệ không
        try {
            ApplicationStatus.valueOf(status.name());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Trạng thái không hợp lệ");
        }

        JobApplication application = jobApplicationRepository.findById(applicationId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy đơn ứng tuyển"));
        
        // Lưu trạng thái cũ để kiểm tra có thay đổi không
        ApplicationStatus oldStatus = application.getStatus();
        
        // Cập nhật trạng thái mới
        application.setStatus(status);
        JobApplication updatedApplication = jobApplicationRepository.save(application);

        // Chỉ gửi email và thông báo nếu trạng thái thực sự thay đổi và là APPROVED hoặc REJECTED
        if (oldStatus != status && (status == ApplicationStatus.APPROVED || status == ApplicationStatus.REJECTED)) {
            try {
                // Gửi email thông báo cho ứng viên
                emailService.sendApplicationStatusEmail(updatedApplication);
                
                // Tạo thông báo trong hệ thống cho ứng viên
                String title = "Cập nhật trạng thái đơn ứng tuyển";
                String content = String.format("Đơn ứng tuyển của bạn cho vị trí %s tại %s đã được %s",
                    application.getJob().getTitle(),
                    application.getEmployer().getCompanyName(),
                    status == ApplicationStatus.APPROVED ? "chấp nhận" : "từ chối");
                
                notificationService.createNotification(
                    application.getApplicant(),
                    title,
                    content,
                    NotificationType.APPLICATION_STATUS,
                    application
                );

                // Tạo thông báo cho employer
                notificationService.notifyJobStatusToEmployer(
                    application.getEmployer().getUser(),
                    application.getJob().getTitle(),
                    status == ApplicationStatus.APPROVED,
                    application
                );

            } catch (MessagingException e) {
                log.error("Lỗi khi gửi email thông báo: {}", e.getMessage());
                // Không throw exception để không ảnh hưởng đến việc cập nhật trạng thái
            }
        }

        return convertToDTO(updatedApplication);
    }

    @Transactional
    public JobApplicationDTO markAsViewed(Long applicationId) {
        JobApplication application = jobApplicationRepository.findById(applicationId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy đơn ứng tuyển"));
        
        application.setEmployerViewed(true);
        JobApplication updatedApplication = jobApplicationRepository.save(application);
        return convertToDTO(updatedApplication);
    }

    public JobApplication getJobApplicationById(Long id) {
        return jobApplicationRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("Không tìm thấy đơn ứng tuyển với id: " + id));
    }

    private JobApplicationDTO convertToDTO(JobApplication application) {

        return JobApplicationDTO.builder()
                .id(application.getId())
                .jobId(application.getJob().getJobId())
                .jobTitle(application.getJob().getTitle())
                .applicantId(application.getApplicant().getId())
                .applicantName(application.getApplicant().getFullName())
                .applicantEmail(application.getApplicant().getEmail())
                .employerId(application.getEmployer().getId())
                .employerName(application.getEmployer().getCompanyName())
                .coverLetter(application.getCoverLetter())
                .resumeUrl(application.getResumeUrl())
                .appliedAt(application.getAppliedAt())
                .status(application.getStatus())
                .employerViewed(application.isEmployerViewed())
                .jobType(application.getJob().getJobType())
                .imageUrl(application.getJob().getImageUrl())
                .build();
    }
} 