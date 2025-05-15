package org.example.goodjobbackend.controller;

import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.dto.JobApplicationDTO;
import org.example.goodjobbackend.dto.JobApplicationRequest;
import org.example.goodjobbackend.model.ApplicationStatus;
import org.example.goodjobbackend.model.JobApplication;
import org.example.goodjobbackend.service.JobApplicationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/applications")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class JobApplicationController {

    private final JobApplicationService jobApplicationService;

    /**
     * API nộp đơn ứng tuyển vào công việc
     * @param request thông tin đơn ứng tuyển
     * @return đơn ứng tuyển sau khi đã được lưu vào hệ thống
     */
    @PostMapping
    public ResponseEntity<JobApplication> apply(@RequestBody JobApplicationRequest request) {
        try {
            JobApplication application = jobApplicationService.apply(request);
            return ResponseEntity.ok(application);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(null);
        }
    }

    /**
     * Lấy danh sách đơn ứng tuyển theo User ID
     */
    @GetMapping("/applicant/{userId}")
    public ResponseEntity<List<JobApplicationDTO>> getApplicationsByUserId(@PathVariable Long userId) {
        return ResponseEntity.ok(jobApplicationService.getApplicationsByUserId(userId));
    }

    /**
     * Lấy danh sách đơn ứng tuyển theo Job ID
     */
    @GetMapping("/job/{jobId}")
    public ResponseEntity<List<JobApplicationDTO>> getApplicationsByJobId(@PathVariable Long jobId) {
        return ResponseEntity.ok(jobApplicationService.getApplicationsByJobId(jobId));
    }

    /**
     * Lấy danh sách đơn ứng tuyển theo Employer ID
     */
    @GetMapping("/employer/{employerId}")
    public ResponseEntity<List<JobApplicationDTO>> getApplicationsByEmployerId(@PathVariable Long employerId) {
        return ResponseEntity.ok(jobApplicationService.getApplicationsByEmployerId(employerId));
    }

    /**
     * Cập nhật trạng thái đơn ứng tuyển
     * Các trạng thái hợp lệ: PENDING, REVIEWING, APPROVED, REJECTED, WITHDRAWN
     */
    @PutMapping("/{applicationId}/status")
    public ResponseEntity<?> updateApplicationStatus(
            @PathVariable Long applicationId,
            @RequestParam ApplicationStatus status) {
        try {
            JobApplicationDTO updatedApplication = jobApplicationService.updateApplicationStatus(applicationId, status);
            return ResponseEntity.ok(updatedApplication);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("Trạng thái không hợp lệ. Các trạng thái hợp lệ: PENDING, REVIEWING, APPROVED, REJECTED, WITHDRAWN");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    /**
     * Đánh dấu đơn ứng tuyển đã được xem bởi employer
     */
    @PutMapping("/{applicationId}/view")
    public ResponseEntity<JobApplicationDTO> markAsViewed(@PathVariable Long applicationId) {
        return ResponseEntity.ok(jobApplicationService.markAsViewed(applicationId));
    }
}
