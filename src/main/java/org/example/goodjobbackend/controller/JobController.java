package org.example.goodjobbackend.controller;

import org.example.goodjobbackend.dto.*;
import org.example.goodjobbackend.model.Job;
import org.example.goodjobbackend.model.JobStatus;
import org.example.goodjobbackend.service.JobService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controller xử lý các API liên quan đến Job
 * Base URL: /api/jobs
 */
@RestController
@RequestMapping("/api/jobs")
@CrossOrigin(origins = "*")
public class JobController {
    private final JobService jobService;

    public JobController(JobService jobService) {
        this.jobService = jobService;
    }

    /**
     * Lấy danh sách tất cả các jobs hoặc jobs của một employer cụ thể với phân trang
     *
     * @param employerId ID của employer (không bắt buộc)
     * @param page Số trang (bắt đầu từ 0)
     * @param size Số lượng items mỗi trang
     * @param sort Sắp xếp (ví dụ: "postedAt,desc")
     * @return Danh sách jobs đã phân trang
     *
     * GET /api/jobs?page=0&size=10&sort=postedAt,desc - Lấy tất cả jobs có phân trang
     * GET /api/jobs?employerId=123&page=0&size=10 - Lấy jobs của employer có ID = 123 có phân trang
     */
    @GetMapping
    public ResponseEntity<Page<JobDTO>> getAllJobs(
            @RequestParam(required = false) Long employerId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "postedAt,desc") String sort) {

        String[] sortParams = sort.split(",");
        Sort.Direction direction = sortParams.length > 1 ?
                Sort.Direction.fromString(sortParams[1]) : Sort.Direction.DESC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortParams[0]));

        Page<Job> jobPage;
        if (employerId != null) {
            jobPage = jobService.getJobsByEmployer(employerId, pageable);
        } else {
            jobPage = jobService.getAllJobs(pageable);
        }

        List<JobDTO> jobDTOs = jobPage.getContent().stream()
                .map(JobDTO::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new PageImpl<>(jobDTOs, pageable, jobPage.getTotalElements()));
    }

    /**
     * Lấy danh sách các jobs đã được duyệt (APPROVED) với phân trang
     *
     * @param page Số trang (bắt đầu từ 0)
     * @param size Số lượng items mỗi trang
     * @param sort Sắp xếp (ví dụ: "postedAt,desc")
     * @return Danh sách jobs đã duyệt có phân trang
     *
     * GET /api/jobs/approved?page=0&size=10&sort=postedAt,desc
     */
    @GetMapping("/approved")
    public ResponseEntity<Page<JobDTO>> getApprovedJobs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "postedAt,desc") String sort) {

        String[] sortParams = sort.split(",");
        Sort.Direction direction = sortParams.length > 1 ?
                Sort.Direction.fromString(sortParams[1]) : Sort.Direction.DESC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortParams[0]));
        Page<Job> jobPage = jobService.getJobsByStatus(JobStatus.APPROVED, pageable);

        List<JobDTO> jobDTOs = jobPage.getContent().stream()
                .map(JobDTO::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new PageImpl<>(jobDTOs, pageable, jobPage.getTotalElements()));
    }

    /**
     * Lấy thông tin chi tiết của một job theo ID
     *
     * @param jobId ID của job cần lấy thông tin
     * @return Thông tin chi tiết của job
     *
     * GET /api/jobs/{jobId}
     */
    @GetMapping("/{jobId}")
    public ResponseEntity<JobDTO> getJobById(@PathVariable Long jobId) {
        Job job = jobService.getJobById(jobId);
        return ResponseEntity.ok(JobDTO.fromEntity(job));
    }

    /**
     * Tạo một job mới
     *
     * @param jobRequest Thông tin job cần tạo
     * @return Job đã được tạo
     *
     * POST /api/jobs
     * Body: JobRequest object
     */
    @PostMapping
    public ResponseEntity<Job> createJob(@RequestBody JobRequest jobRequest) {
        return ResponseEntity.ok(jobService.createJob(jobRequest));
    }

    /**
     * Cập nhật thông tin của một job
     *
     * @param jobId ID của job cần cập nhật
     * @param jobRequest Thông tin mới cần cập nhật
     * @return Job đã được cập nhật
     *
     * PUT /api/jobs/{jobId}
     * Body: JobRequest object
     */
    @PutMapping("/{jobId}")
    public ResponseEntity<Job> updateJob(@PathVariable Long jobId, @RequestBody JobRequest jobRequest) {
        return ResponseEntity.ok(jobService.updateJob(jobId, jobRequest));
    }

    /**
     * Xóa một job (chuyển trạng thái thành DELETED)
     *
     * @param jobId ID của job cần xóa
     * @param adminId ID của admin thực hiện xóa
     * @return ResponseEntity với status 200 nếu xóa thành công
     *
     * DELETE /api/jobs/{jobId}?adminId=123
     */
    @DeleteMapping("/{jobId}")
    public ResponseEntity<Void> deleteJob(
            @PathVariable Long jobId,
            @RequestParam Long adminId) {
        JobProcessRequest processRequest = new JobProcessRequest();
        processRequest.setAdminId(adminId);
        processRequest.setStatus(JobStatus.DELETED);
        jobService.processJob(jobId, processRequest);
        return ResponseEntity.ok().build();
    }

    /**
     * Tăng số lượt xem của một job
     *
     * @param jobId ID của job cần tăng lượt xem
     * @return ResponseEntity với status 200 nếu thành công
     *
     * POST /api/jobs/{jobId}/view
     */
    @PostMapping("/{jobId}/view")
    public ResponseEntity<Void> incrementViewCount(@PathVariable Long jobId) {
        jobService.incrementViewCount(jobId);
        return ResponseEntity.ok().build();
    }

    /**
     * Tăng số lượt ứng tuyển của một job
     *
     * @param jobId ID của job cần tăng lượt ứng tuyển
     * @return ResponseEntity với status 200 nếu thành công
     *
     * POST /api/jobs/{jobId}/apply
     */
    @PostMapping("/{jobId}/apply")
    public ResponseEntity<Void> incrementApplyCount(@PathVariable Long jobId) {
        jobService.incrementApplyCount(jobId);
        return ResponseEntity.ok().build();
    }

    /**
     * Helper method để chuyển đổi từ Job sang JobRequest
     * Được sử dụng khi cần cập nhật job
     */
    private JobRequest convertJobToRequest(Job job) {
        JobRequest request = new JobRequest();
        request.setEmployerId(job.getEmployer().getUser().getId());
        request.setTitle(job.getTitle());
        request.setDescription(job.getDescription());
        request.setRequirement(job.getRequirement());
        request.setLocation(job.getLocation());
        request.setJobType(job.getJobType());
        request.setSalaryMin(job.getSalaryMin());
        request.setSalaryMax(job.getSalaryMax());
        request.setSalaryCurrency(job.getSalaryCurrency());
        request.setExpireAt(job.getExpireAt());
        request.setIsSalaryPublic(job.getIsSalaryPublic());
        request.setImageUrl(job.getImageUrl());
        return request;
    }

    /**
     * Lấy danh sách job của một user cụ thể với phân trang
     *
     * @param userId ID của user cần lấy danh sách job
     * @param page Số trang (bắt đầu từ 0)
     * @param size Số lượng items mỗi trang
     * @param sort Sắp xếp (ví dụ: "postedAt,desc")
     * @return Danh sách job của user có phân trang
     *
     * GET /api/jobs/by-user/{userId}?page=0&size=10&sort=postedAt,desc
     */
    @GetMapping("/by-user/{userId}")
    public ResponseEntity<Page<JobDTO>> getAllJobsByUserId(
            @PathVariable Long userId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "postedAt,desc") String sort) {

        String[] sortParams = sort.split(",");
        Sort.Direction direction = sortParams.length > 1 ?
                Sort.Direction.fromString(sortParams[1]) : Sort.Direction.DESC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortParams[0]));
        Page<Job> jobPage = jobService.getAllJobsByUserId(userId, pageable);

        List<JobDTO> jobDTOs = jobPage.getContent().stream()
                .map(JobDTO::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok()
                .header("Cache-Control", "no-cache, no-store, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Expires", "0")
                .body(new PageImpl<>(jobDTOs, pageable, jobPage.getTotalElements()));
    }

    /**
     * Tìm kiếm jobs với bộ lọc và phân trang
     *
     * @param keyword Từ khóa tìm kiếm trong tiêu đề, mô tả, yêu cầu
     * @param location Vị trí của job
     * @param minSalary Mức lương tối thiểu
     * @param maxSalary Mức lương tối đa
     * @param page Số trang (bắt đầu từ 0)
     * @param size Số lượng items mỗi trang
     * @param sort Sắp xếp (ví dụ: "postedAt,desc")
     * @return Danh sách jobs phù hợp với bộ lọc
     *
     * GET /api/jobs/search?keyword=Java&location=Hanoi&minSalary=30000&maxSalary=50000&page=0&size=10&sort=postedAt,desc
     */
    @GetMapping("/search")
    public ResponseEntity<Page<JobDTO>> searchJobs(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String location,
            @RequestParam(required = false) Double minSalary,
            @RequestParam(required = false) Double maxSalary,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id,desc") String[] sort) {

        // Validate page and size
        if (page < 0) {
            throw new IllegalArgumentException("Page index must not be less than zero!");
        }
        if (size < 1) {
            throw new IllegalArgumentException("Page size must not be less than one!");
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by(getSortOrders(sort)));
        Page<Job> jobPage = jobService.searchJobs(keyword, location, minSalary, maxSalary, pageable);

        // Convert to DTOs
        List<JobDTO> jobDTOs = jobPage.getContent().stream()
                .map(JobDTO::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new PageImpl<>(jobDTOs, pageable, jobPage.getTotalElements()));
    }

    /**
     * Tìm kiếm jobs theo trạng thái với bộ lọc và phân trang
     *
     * @param keyword Từ khóa tìm kiếm trong tiêu đề, mô tả, yêu cầu
     * @param location Vị trí của job
     * @param minSalary Mức lương tối thiểu
     * @param maxSalary Mức lương tối đa
     * @param status Trạng thái của job (PENDING, APPROVED, REJECTED, DELETED)
     * @param page Số trang (bắt đầu từ 0)
     * @param size Số lượng items mỗi trang
     * @param sort Sắp xếp (ví dụ: "postedAt,desc")
     * @return Danh sách jobs theo trạng thái và bộ lọc
     *
     * GET /api/jobs/search/status/APPROVED?keyword=Java&location=Hanoi&minSalary=30000&maxSalary=50000&page=0&size=10&sort=postedAt,desc
     */
    @GetMapping("/search/status/{status}")
    public ResponseEntity<Page<JobDTO>> searchJobsByStatus(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String location,
            @RequestParam(required = false) Double minSalary,
            @RequestParam(required = false) Double maxSalary,
            @PathVariable JobStatus status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "postedAt,desc") String sort) {

        String[] sortParams = sort.split(",");
        Sort.Direction direction = sortParams.length > 1 ?
                Sort.Direction.fromString(sortParams[1]) : Sort.Direction.DESC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortParams[0]));
        Page<Job> jobPage = jobService.searchJobsByStatus(keyword, location, minSalary, maxSalary, status, pageable);

        List<JobDTO> jobDTOs = jobPage.getContent().stream()
                .map(JobDTO::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new PageImpl<>(jobDTOs, pageable, jobPage.getTotalElements()));
    }

    /**
     * Helper method để chuyển đổi mảng các chuỗi sắp xếp thành danh sách Sort.Order
     * Ví dụ: ["createdAt", "desc", "id", "asc"] -> [Order(createdAt,DESC), Order(id,ASC)]
     */
    private List<Sort.Order> getSortOrders(String[] sort) {
        List<Sort.Order> orders = new ArrayList<>();

        if (sort[0].contains(",")) {
            // sort=[field,direction]
            for (String sortOrder : sort) {
                String[] _sort = sortOrder.split(",");
                orders.add(new Sort.Order(getSortDirection(_sort[1]), _sort[0]));
            }
        } else {
            // sort=[field, direction, field, direction...]
            for (int i = 0; i < sort.length; i += 2) {
                orders.add(new Sort.Order(
                        getSortDirection(sort[i + 1]),
                        sort[i]
                ));
            }
        }
        return orders;
    }

    /**
     * Helper method để chuyển đổi chuỗi direction thành Sort.Direction
     */
    private Sort.Direction getSortDirection(String direction) {
        if (direction.equals("asc")) {
            return Sort.Direction.ASC;
        } else if (direction.equals("desc")) {
            return Sort.Direction.DESC;
        }
        return Sort.Direction.ASC;
    }

    @GetMapping("/all")
    public ResponseEntity<List<JobDTO>> getAllJobsNoPaging() {
        List<Job> jobs = jobService.getAllJobs();
        List<JobDTO> jobDTOs = jobs.stream()
                .map(JobDTO::fromEntity)
                .collect(Collectors.toList());
        return ResponseEntity.ok(jobDTOs);
    }

    /**
     * Lấy tất cả jobs đã duyệt (APPROVED) (không phân trang)
     * GET /api/jobs/approved/all
     */
    @GetMapping("/approved/all")
    public ResponseEntity<List<JobDTO>> getApprovedJobs() {
        List<Job> jobs = jobService.getJobsByStatus(JobStatus.APPROVED);
        List<JobDTO> jobDTOs = jobs.stream()
                .map(JobDTO::fromEntity)
                .collect(Collectors.toList());
        return ResponseEntity.ok(jobDTOs);
    }

    /**
     * Lấy tất cả jobs theo trạng thái chỉ định (không phân trang)
     * GET /api/jobs/status/{status}
     */
    @GetMapping("/status/{status}")
    public ResponseEntity<List<JobDTO>> getJobsByStatus(@PathVariable JobStatus status) {
        List<Job> jobs = jobService.getJobsByStatus(status);
        List<JobDTO> jobDTOs = jobs.stream()
                .map(JobDTO::fromEntity)
                .collect(Collectors.toList());
        return ResponseEntity.ok(jobDTOs);
    }

    // Lấy tổng số lượt xem và lượt ứng tuyển
    @GetMapping("/statistics")
    public Map<String, Long> getJobStatistics() {
        Long totalViews = jobService.getTotalViewCount();
        Long totalApplies = jobService.getTotalApplyCount();

        Map<String, Long> stats = new HashMap<>();
        stats.put("totalViews", totalViews != null ? totalViews : 0L);
        stats.put("totalApplies", totalApplies != null ? totalApplies : 0L);

        return stats;
    }

    @GetMapping("/status/count")
    public ResponseEntity<List<JobCountDTO>> getJobCountsByStatus() {
        List<JobCountDTO> jobCounts = jobService.getJobCountsByStatus();
        return ResponseEntity.ok(jobCounts);
    }

    @PostMapping("/{jobId}/delete")
    public ResponseEntity<Job> deleteJob(
            @PathVariable Long jobId
    ) {
        JobProcessRequest request = new JobProcessRequest();
        request.setStatus(JobStatus.DELETED);
        return ResponseEntity.ok(jobService.processJob(jobId, request));
    }


    @GetMapping("/search/stats")
    public ResponseEntity<List<JobSearchStats>> getJobSearchStats(
            @RequestParam(required = false, defaultValue = "") String keyword) {
        return ResponseEntity.ok(jobService.getJobSearchStats(keyword));
    }

}