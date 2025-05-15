package org.example.goodjobbackend.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.dto.EmployerSetupRequest;
import org.example.goodjobbackend.dto.EmployerUpdateRequest;
import org.example.goodjobbackend.dto.EmployerDTO;
import org.example.goodjobbackend.service.EmployerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/employers")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class EmployerController {

    private final EmployerService employerService;

    /**
     * Setup thông tin employer mới
     * POST /api/employers/setup?userId={userId}
     */
    @PostMapping("/setup")
    public ResponseEntity<EmployerDTO> setupEmployerProfile(
            @RequestParam Long userId,
            @Valid @RequestBody EmployerSetupRequest request) {
        return ResponseEntity.ok(employerService.setupEmployerProfile(userId, request));
    }

    /**
     * Lấy thông tin employer profile
     * GET /api/employers/profile?userId={userId}
     */
    @GetMapping("/profile")
    public ResponseEntity<EmployerDTO> getEmployerProfile(@RequestParam Long userId) {
        return ResponseEntity.ok(employerService.getEmployerProfile(userId));
    }

    /**
     * Cập nhật thông tin employer
     * PUT /api/employers/profile?userId={userId}
     */
    @PutMapping("/profile")
    public ResponseEntity<EmployerDTO> updateEmployerProfile(
            @RequestParam Long userId,
            @Valid @RequestBody EmployerSetupRequest request) {
        return ResponseEntity.ok(employerService.updateEmployerProfile(userId, request));
    }

    /**
     * Lấy thông tin employer theo ID
     * GET /api/employers/{id}
     */
    @GetMapping("/{id}")
    public ResponseEntity<EmployerDTO> findEmployerById(@PathVariable Long id) {
        return ResponseEntity.ok(employerService.findEmployerById(id));
    }

    /**
     * Cập nhật thông tin employer với EmployerUpdateRequest
     * PUT /api/employers/{id}
     */
    @PutMapping("/{id}")
    public ResponseEntity<EmployerDTO> updateEmployer(
            @PathVariable Long id,
            @Valid @RequestBody EmployerUpdateRequest request) {
        return ResponseEntity.ok(employerService.updateEmployer(id, request));
    }

    /**
     * Lấy thông tin employer theo user ID
     * GET /api/employers/user/{userId}
     */
    @GetMapping("/user/{userId}")
    public ResponseEntity<EmployerDTO> getEmployerByUserId(@PathVariable Long userId) {
        return ResponseEntity.ok(employerService.getEmployerByUserId(userId));
    }

    /**
     * Kiểm tra xem một user có phải là employer hay không
     * GET /api/employers/{id}/check
     */
    @GetMapping("/{id}/check")
    public ResponseEntity<Boolean> checkEmployer(@PathVariable Long id) {
        return ResponseEntity.ok(employerService.isEmployer(id));
    }

    /**
     * Lấy thông tin của employer hiện tại
     * GET /api/employers/current
     */
    @GetMapping("/current")
    public ResponseEntity<EmployerDTO> getCurrentEmployer() {
        return ResponseEntity.ok(employerService.getCurrentEmployer());
    }
}