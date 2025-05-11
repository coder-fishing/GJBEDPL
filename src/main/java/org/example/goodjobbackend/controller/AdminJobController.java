package org.example.goodjobbackend.controller;

import org.example.goodjobbackend.dto.JobProcessRequest;
import org.example.goodjobbackend.model.Job;
import org.example.goodjobbackend.model.JobStatus;
import org.example.goodjobbackend.service.JobService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller xử lý các API dành cho Admin
 * Base URL: /api/admin/jobs
 * 
 * Note về adminId:
 * - Hiện tại adminId là bắt buộc cho mọi thao tác
 * - Nếu muốn làm adminId không bắt buộc, thêm:
 *   @RequestParam(required = false, defaultValue = "1") Long adminId
 * - Hoặc thêm biến DEFAULT_ADMIN_ID = 1L vào class
 */
@RestController
@RequestMapping("/api/admin/jobs")
@CrossOrigin(origins = "*")  // Cho phép CORS
public class AdminJobController {
    private final JobService jobService;

    // Có thể thêm giá trị mặc định cho adminId nếu cần
    // private static final Long DEFAULT_ADMIN_ID = 1L;

    public AdminJobController(JobService jobService) {
        this.jobService = jobService;
    }

    /**
     * Lấy danh sách công việc theo trạng thái
     * GET /api/admin/jobs/status/{status}
     */
    @GetMapping("/status/{status}")
    public ResponseEntity<List<Job>> getJobsByStatus(@PathVariable JobStatus status) {
        return ResponseEntity.ok(jobService.getJobsByStatus(status));
    }

    /**
     * Lấy danh sách công việc chờ duyệt
     * GET /api/admin/jobs/pending
     */
    @GetMapping("/pending")
    public ResponseEntity<List<Job>> getPendingJobs() {
        return ResponseEntity.ok(jobService.getJobsByStatus(JobStatus.PENDING));
    }

    /**
     * Xử lý công việc (duyệt/từ chối/xóa)
     * POST /api/admin/jobs/{jobId}/process
     * 
     * Body: {
     *   "status": "APPROVED/REJECTED/DELETED",
     *   "adminId": 123,
     *   "rejectionReason": "Lý do từ chối (nếu reject)"
     * }
     */
    @PostMapping("/{jobId}/process")
    public ResponseEntity<Job> processJob(
            @PathVariable Long jobId,
            @RequestBody JobProcessRequest processRequest)
    {
        return ResponseEntity.ok(jobService.processJob(jobId, processRequest));
    }

    /**
     * API nhanh để duyệt công việc
     * POST /api/admin/jobs/{jobId}/approve?adminId=123
     * 
     * Note: Để làm adminId không bắt buộc, sửa thành:
     * @RequestParam(required = false, defaultValue = "1") Long adminId
     */
    @PostMapping("/{jobId}/approve")
    public ResponseEntity<Job> approveJob(
            @PathVariable Long jobId,
            @RequestParam(required = false, defaultValue = "1") Long adminId)
    {
        JobProcessRequest request = new JobProcessRequest();
        request.setStatus(JobStatus.APPROVED);
        request.setAdminId(adminId);
        return ResponseEntity.ok(jobService.processJob(jobId, request));
    }

    /**
     * API để từ chối công việc
     * POST /api/admin/jobs/{jobId}/reject
     * Body: {
     *   "adminId": 1, (optional)
     *   "rejectionReason": "Lý do từ chối"
     * }
     */
    @PostMapping("/{jobId}/reject")
    public ResponseEntity<Job> rejectJob(
            @PathVariable Long jobId,
            @RequestBody JobProcessRequest request)
    {
        if (request.getAdminId() == null) {
            request.setAdminId(1L);
        }
        request.setStatus(JobStatus.REJECTED);
        return ResponseEntity.ok(jobService.processJob(jobId, request));
    }

    /**
     * API nhanh để xóa công việc
     * POST /api/admin/jobs/{jobId}/delete?adminId=123
     * 
     * Note: Để làm adminId không bắt buộc, sửa thành:
     * @RequestParam(required = false, defaultValue = "1") Long adminId
     */
    @PostMapping("/{jobId}/delete")
    public ResponseEntity<Job> deleteJob(
            @PathVariable Long jobId,
            @RequestParam(required = false, defaultValue = "1") Long adminId)
    {
        JobProcessRequest request = new JobProcessRequest();
        request.setStatus(JobStatus.DELETED);
        request.setAdminId(adminId);
        return ResponseEntity.ok(jobService.processJob(jobId, request));
    }
} 