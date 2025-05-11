package org.example.goodjobbackend.service;

import jakarta.persistence.EntityNotFoundException;
import org.example.goodjobbackend.dto.ChangePasswordRequest;
import org.example.goodjobbackend.dto.UserBasicDTO;
import org.example.goodjobbackend.dto.UserStatusRequest;
import org.example.goodjobbackend.dto.UserUpdateRequest;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.UserRole;
import org.example.goodjobbackend.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User createUser(OAuth2User oAuth2User) {
        User user = new User();
        // Set user attributes from OAuth2User
        user.setFullName(oAuth2User.getAttribute("name"));
        user.setEmail(oAuth2User.getAttribute("email"));
        return user;
    }

    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));
    }

    @Transactional
    public User updateUser(Long userId, UserUpdateRequest updateRequest) {
        User user = getUserById(userId);

        // Cập nhật thông tin nếu có thay đổi
        if (updateRequest.getFullName() != null) {
            user.setFullName(updateRequest.getFullName());
        }
        if (updateRequest.getPhoneNumber() != null) {
            user.setPhoneNumber(updateRequest.getPhoneNumber());
        }
        if (updateRequest.getAvatarUrl() != null) {
            user.setAvatarUrl(updateRequest.getAvatarUrl());
        }
        if (updateRequest.getBio() != null) {
            user.setBio(updateRequest.getBio());
        }

        return userRepository.save(user);
    }

    private UserBasicDTO convertToBasicDTO(User user) {
        UserBasicDTO dto = new UserBasicDTO();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setFullName(user.getFullName());
        dto.setEmail(user.getEmail());
        dto.setPhoneNumber(user.getPhoneNumber());
        dto.setAvatarUrl(user.getAvatarUrl());
        dto.setBio(user.getBio());
        dto.setRole(user.getRole());
        dto.setActive(user.isActive());
        dto.setEnabled(user.isEnabled());
        return dto;
    }

    /**
     * Get all users with USER role
     * @return List of users with USER role
     */
    public List<UserBasicDTO> getAllNormalUsers() {
        return userRepository.findByRole(UserRole.USER)
                .stream()
                .map(this::convertToBasicDTO)
                .collect(Collectors.toList());
    }

    /**
     * Get all users with EMPLOYER role
     * @return List of users with EMPLOYER role
     */
    public List<UserBasicDTO> getAllEmployers() {
        return userRepository.findByRole(UserRole.EMPLOYER)
                .stream()
                .map(this::convertToBasicDTO)
                .collect(Collectors.toList());
    }

    /**
     * Cập nhật trạng thái hoạt động của user
     * @param userId ID của user
     * @param statusRequest Request chứa trạng thái mới
     * @return User đã được cập nhật
     */
    @Transactional
    public User updateUserStatus(Long userId, UserStatusRequest statusRequest) {
        User user = getUserById(userId);
        user.setActive(statusRequest.isActive());
        return userRepository.save(user);
    }

    /**
     * Lấy trạng thái hoạt động của user
     * @param userId ID của user
     * @return true nếu user đang hoạt động, false nếu không
     */
    public boolean getUserStatus(Long userId) {
        User user = getUserById(userId);
        return user.isActive();
    }

    /**
     * Đổi mật khẩu cho user
     * @param userId ID của user
     * @param request thông tin mật khẩu mới
     * @throws RuntimeException nếu mật khẩu hiện tại không đúng hoặc mật khẩu mới không khớp
     */
    @Transactional
    public void changePassword(Long userId, ChangePasswordRequest request) {
        User user = getUserById(userId);

        // Kiểm tra nếu là tài khoản OAuth2
        if (user.isOAuth2User()) {
            throw new RuntimeException("Không thể đổi mật khẩu cho tài khoản đăng nhập bằng Google");
        }

        // Kiểm tra mật khẩu hiện tại
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new RuntimeException("Mật khẩu hiện tại không đúng");
        }

        // Kiểm tra mật khẩu mới và xác nhận mật khẩu
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new RuntimeException("Mật khẩu mới và xác nhận mật khẩu không khớp");
        }

        // Cập nhật mật khẩu mới
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }
}