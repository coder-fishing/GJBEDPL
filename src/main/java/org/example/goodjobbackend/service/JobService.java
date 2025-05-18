package org.example.goodjobbackend.service;

import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import org.example.goodjobbackend.dto.*;
import org.example.goodjobbackend.model.*;
import org.example.goodjobbackend.repository.JobRepository;
import org.example.goodjobbackend.repository.UserRepository;
import org.example.goodjobbackend.repository.EmployerRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JobService {
    private final JobRepository jobRepository;
    private final UserRepository userRepository;
    private final EmployerRepository employerRepository;
    private final AdminNotificationService adminNotificationService;
    private final TestDataService testDataService;

    // Lấy toàn bộ danh sách công việc (phân trang)
    public Page<Job> getAllJobs(Pageable pageable) {
        return jobRepository.findAll(pageable);
    }

    // Lấy toàn bộ danh sách công việc (không phân trang)
    public List<Job> getAllJobs() {
        return jobRepository.findAll();
    }

    // Lấy danh sách công việc có status = APPROVED (không phân trang)
    public List<Job> getAllApprovedJobs() {
        return jobRepository.findAllApproved();
    }

    // Lấy danh sách công việc có status = PENDING (không phân trang)
    public List<Job> getAllPendingJobs() {
        return jobRepository.findAllPending();
    }

    // Lấy danh sách công việc có status = REJECTED (không phân trang)
    public List<Job> getAllRejectedJobs() {
        return jobRepository.findAllRejected();
    }

    // Lấy danh sách công việc có status = DELETED (không phân trang)
    public List<Job> getAllDeletedJobs() {
        return jobRepository.findAllDeleted();
    }

    // Lấy danh sách công việc theo trạng thái (phân trang)
    public Page<Job> getJobsByStatus(JobStatus status, Pageable pageable) {
        return jobRepository.findByStatus(status, pageable);
    }

    // Lấy danh sách công việc theo trạng thái (không phân trang)
    public List<Job> getJobsByStatus(JobStatus status) {
        return jobRepository.findByStatus(status);
    }

    // Lấy danh sách công việc theo employer (phân trang)
    public Page<Job> getJobsByEmployer(Long userId, Pageable pageable) {
        Employer employer = employerRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy thông tin nhà tuyển dụng"));
        return jobRepository.findByEmployer(employer, pageable);
    }

    // Lấy danh sách công việc theo employer (không phân trang)
    public List<Job> getJobsByEmployer(Long userId) {
        Employer employer = employerRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy thông tin nhà tuyển dụng"));
        return jobRepository.findByEmployer(employer);
    }

    // Lấy công việc theo ID
    public Job getJobById(Long jobId) {
        return jobRepository.findById(jobId)
                .orElseThrow(() -> new EntityNotFoundException("Không tìm thấy công việc với id: " + jobId));
    }

    // Tạo công việc mới
    @Transactional
    public Job createJob(JobRequest jobRequest) {
        Employer employer = employerRepository.findByUserId(jobRequest.getEmployerId())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy thông tin nhà tuyển dụng"));

        Job job = new Job();
        job.setEmployerId(employer.getId());
        updateJobFromRequest(job, jobRequest);
        Job savedJob = jobRepository.save(job);
        
        // Create admin notification for job creation
        User user = employer.getUser();
        adminNotificationService.createNotification(
                AdminAction.CREATE, 
                savedJob, 
                user, 
                "Công việc mới được tạo: " + savedJob.getTitle()
        );
        
        return savedJob;
    }

    // Cập nhật công việc
    @Transactional
    public Job updateJob(Long jobId, JobRequest jobRequest) {
        Job job = getJobById(jobId);
        Employer employer = employerRepository.findByUserId(jobRequest.getEmployerId())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy thông tin nhà tuyển dụng"));

        if (!job.getEmployerId().equals(employer.getId())) {
            throw new IllegalStateException("Không có quyền cập nhật công việc này");
        }
        updateJobFromRequest(job, jobRequest);
        Job updatedJob = jobRepository.save(job);
        
        // Create admin notification for job update
        User user = employer.getUser();
        adminNotificationService.createNotification(
                AdminAction.UPDATE, 
                updatedJob, 
                user, 
                "Công việc được cập nhật: " + updatedJob.getTitle()
        );
        
        return updatedJob;
    }

    // Xử lý trạng thái công việc (APPROVED, REJECTED, DELETED)
    @Transactional
    public Job processJob(Long jobId, JobProcessRequest processRequest) {
        Job job = getJobById(jobId);
        User admin = userRepository.findById(processRequest.getAdminId())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy admin"));

        JobStatus oldStatus = job.getStatus();
        job.setStatus(processRequest.getStatus());
        job.setProcessedBy(admin);
        job.setProcessedAt(LocalDateTime.now());

        if (processRequest.getStatus() == JobStatus.REJECTED) {
            if (processRequest.getRejectionReason() == null || processRequest.getRejectionReason().trim().isEmpty()) {
                throw new IllegalArgumentException("Lý do từ chối là bắt buộc khi từ chối công việc");
            }
            job.setRejectionReason(processRequest.getRejectionReason());
        }

        if (processRequest.getStatus() == JobStatus.DELETED) {
            job.setIsActive(false);
        }

        Job processedJob = jobRepository.save(job);
        
        // Create admin notification for job processing
        AdminAction action;
        String description;
        
        if (processRequest.getStatus() == JobStatus.APPROVED) {
            action = AdminAction.APPROVE;
            description = "Công việc được phê duyệt: " + processedJob.getTitle();
        } else if (processRequest.getStatus() == JobStatus.REJECTED) {
            action = AdminAction.REJECT;
            description = "Công việc bị từ chối: " + processedJob.getTitle() + ". Lý do: " + processRequest.getRejectionReason();
        } else if (processRequest.getStatus() == JobStatus.DELETED) {
            action = AdminAction.DELETE;
            description = "Công việc bị xóa: " + processedJob.getTitle();
        } else {
            action = AdminAction.UPDATE;
            description = "Trạng thái công việc thay đổi từ " + oldStatus + " thành " + processRequest.getStatus() + ": " + processedJob.getTitle();
        }
        
        adminNotificationService.createNotification(action, processedJob, admin, description);
        
        return processedJob;
    }

    // Test mode method to process a job without requiring admin validation
    @Transactional
    public Job processJobForTesting(Long jobId, JobStatus newStatus, String rejectionReason) {
        Job job = getJobById(jobId);
        User testAdmin = testDataService.getMockAdminUser();
        
        JobStatus oldStatus = job.getStatus();
        job.setStatus(newStatus);
        job.setProcessedBy(testAdmin);
        job.setProcessedAt(LocalDateTime.now());

        if (newStatus == JobStatus.REJECTED) {
            if (rejectionReason == null || rejectionReason.trim().isEmpty()) {
                rejectionReason = "Rejected for testing purposes";
            }
            job.setRejectionReason(rejectionReason);
        }

        if (newStatus == JobStatus.DELETED) {
            job.setIsActive(false);
        }

        Job processedJob = jobRepository.save(job);
        
        // Create admin notification for job processing
        AdminAction action;
        String description;
        
        if (newStatus == JobStatus.APPROVED) {
            action = AdminAction.APPROVE;
            description = "Công việc được phê duyệt: " + processedJob.getTitle();
        } else if (newStatus == JobStatus.REJECTED) {
            action = AdminAction.REJECT;
            description = "Công việc bị từ chối: " + processedJob.getTitle() + ". Lý do: " + rejectionReason;
        } else if (newStatus == JobStatus.DELETED) {
            action = AdminAction.DELETE;
            description = "Công việc bị xóa: " + processedJob.getTitle();
        } else {
            action = AdminAction.UPDATE;
            description = "Trạng thái công việc thay đổi từ " + oldStatus + " thành " + newStatus + ": " + processedJob.getTitle();
        }
        
        adminNotificationService.createNotification(action, processedJob, testAdmin, description);
        
        return processedJob;
    }

    // Tăng số lượt xem
    @Transactional
    public void incrementViewCount(Long jobId) {
        jobRepository.incrementViewCount(jobId);
    }

    // Tăng số lượt ứng tuyển
    @Transactional
    public void incrementApplyCount(Long jobId) {
        jobRepository.incrementApplyCount(jobId);
    }

    // Cập nhật thông tin công việc từ request
    private void updateJobFromRequest(Job job, JobRequest request) {
        job.setTitle(request.getTitle());
        job.setDescription(request.getDescription());
        job.setRequirement(request.getRequirement());
        job.setLocation(request.getLocation());
        job.setJobType(request.getJobType());
        job.setSalaryMin(request.getSalaryMin());
        job.setSalaryMax(request.getSalaryMax());
        job.setSalaryCurrency(request.getSalaryCurrency());
        job.setExpireAt(request.getExpireAt());
        job.setIsSalaryPublic(request.getIsSalaryPublic());
        job.setImageUrl(request.getImageUrl());
    }

    // Lấy danh sách công việc theo userId (phân trang)
    public Page<Job> getAllJobsByUserId(Long userId, Pageable pageable) {
        Employer employer = employerRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy thông tin nhà tuyển dụng"));
        return jobRepository.findByEmployer(employer, pageable);
    }

    // Lấy danh sách công việc theo userId (không phân trang)
    public List<Job> getAllJobsByUserId(Long userId) {
        Employer employer = employerRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy thông tin nhà tuyển dụng"));
        return jobRepository.findByEmployer(employer);
    }

    // Tìm kiếm công việc với bộ lọc (mặc định status = APPROVED)
    public Page<Job> searchJobs(String keyword, String location, Double minSalary, Double maxSalary, Pageable pageable) {
        return jobRepository.searchWithFilters(keyword, location, minSalary, maxSalary, pageable);
    }

    // Tìm kiếm công việc theo trạng thái với bộ lọc
    public Page<Job> searchJobsByStatus(String keyword, String location, Double minSalary, Double maxSalary, JobStatus status, Pageable pageable) {
        return jobRepository.searchWithFiltersAndStatus(keyword, location, minSalary, maxSalary, status, pageable);
    }

    // Lấy tổng số lượt xem tất cả công việc
    public Long getTotalViewCount() {
        return jobRepository.getAllView();
    }

    // Lấy tổng số lượt ứng tuyển tất cả công việc
    public Long getTotalApplyCount() {
        return jobRepository.getAllApply();
    }

    public List<JobCountDTO> getJobCountsByStatus() {
        List<Object[]> rawResults = jobRepository.countJobsByStatus();
        List<JobCountDTO> results = new ArrayList<>();
        for (Object[] row : rawResults) {
            JobStatus status = (JobStatus) row[0];
            Long count = (Long) row[1];
            results.add(new JobCountDTO(status, count));
        }
        System.out.println(results);
        return results;
    }

    public List<JobSearchStats> getJobSearchStats(String keyword) {
        List<Object[]> results = jobRepository.countJobsByKeyword(keyword);
        return results.stream()
            .map(result -> new JobSearchStats(
                (String) result[0],  // jobTitle
                ((Number) result[1]).longValue()  // count
            ))
            .collect(Collectors.toList());
    }
}