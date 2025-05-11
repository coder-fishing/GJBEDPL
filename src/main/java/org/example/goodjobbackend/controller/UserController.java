package org.example.goodjobbackend.controller;

import jakarta.validation.Valid;
import org.example.goodjobbackend.dto.ChangePasswordRequest;
import org.example.goodjobbackend.dto.UserBasicDTO;
import org.example.goodjobbackend.dto.UserStatusRequest;
import org.example.goodjobbackend.dto.UserUpdateRequest;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    /**
     * Lấy thông tin của user theo ID
     * 
     * @param userId ID của user cần lấy thông tin
     * @return Thông tin của user
     * 
     * GET /api/users/{userId}
     */
    @GetMapping("/{userId}")
    public ResponseEntity<User> getUserById(@PathVariable Long userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    /**
     * Cập nhật thông tin của user
     * 
     * @param userId ID của user cần cập nhật
     * @param updateRequest Thông tin cần cập nhật
     * @return Thông tin user sau khi cập nhật
     * 
     * PUT /api/users/{userId}
     * Body: UserUpdateRequest object
     */
    @PutMapping("/{userId}")
    public ResponseEntity<User> updateUser(
            @PathVariable Long userId,
            @Valid @RequestBody UserUpdateRequest updateRequest) {
        return ResponseEntity.ok(userService.updateUser(userId, updateRequest));
    }

    /**
     * Lấy danh sách tất cả user với role USER (chỉ thông tin cơ bản)
     * 
     * @return Danh sách các user thường
     * 
     * GET /api/users/normal
     */
    @GetMapping("/normal")
    public ResponseEntity<List<UserBasicDTO>> getAllNormalUsers() {
        return ResponseEntity.ok(userService.getAllNormalUsers());
    }

    /**
     * Lấy danh sách tất cả user với role EMPLOYER (chỉ thông tin cơ bản)
     * 
     * @return Danh sách các employer
     * 
     * GET /api/users/employers
     */
    @GetMapping("/employers")
    public ResponseEntity<List<UserBasicDTO>> getAllEmployers() {
        return ResponseEntity.ok(userService.getAllEmployers());
    }

    /**
     * Lấy trạng thái hoạt động của user
     * 
     * @param userId ID của user cần kiểm tra
     * @return Trạng thái hoạt động của user
     * 
     * GET /api/users/{userId}/status
     */
    @GetMapping("/{userId}/status")
    public ResponseEntity<Map<String, Boolean>> getUserStatus(@PathVariable Long userId) {
        boolean status = userService.getUserStatus(userId);
        return ResponseEntity.ok(Map.of("active", status));
    }

    /**
     * Cập nhật trạng thái hoạt động của user
     * 
     * @param userId ID của user cần cập nhật
     * @param statusRequest Request chứa trạng thái mới
     * @return User sau khi cập nhật
     * 
     * PUT /api/users/{userId}/status
     */
    @PutMapping("/{userId}/status")
    public ResponseEntity<User> updateUserStatus(
            @PathVariable Long userId,
            @Valid @RequestBody UserStatusRequest statusRequest) {
        return ResponseEntity.ok(userService.updateUserStatus(userId, statusRequest));
    }

    /**
     * Đổi mật khẩu cho user
     * 
     * @param userId ID của user cần đổi mật khẩu
     * @param request thông tin mật khẩu mới
     * @return Thông báo kết quả
     * 
     * PUT /api/users/{userId}/password
     * Body: ChangePasswordRequest object
     */
    @PutMapping("/{userId}/password")
    public ResponseEntity<?> changePassword(
            @PathVariable Long userId,
            @Valid @RequestBody ChangePasswordRequest request) {
        try {
            userService.changePassword(userId, request);
            return ResponseEntity.ok(Map.of("message", "Đổi mật khẩu thành công"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
} 