package org.example.goodjobbackend.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.dto.EmployerDTO;
import org.example.goodjobbackend.dto.EmployerSetupRequest;
import org.example.goodjobbackend.dto.EmployerUpdateRequest;
import org.example.goodjobbackend.model.Employer;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.UserRole;
import org.example.goodjobbackend.repository.EmployerRepository;
import org.example.goodjobbackend.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class EmployerService {

    private final EmployerRepository employerRepository;
    private final UserRepository userRepository;

    @Transactional
    public EmployerDTO setupEmployerProfile(Long userId, EmployerSetupRequest request) {
        // Tìm user và lock for update to prevent concurrent modifications
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy user"));

        // Kiểm tra role
        if (user.getRole() != UserRole.EMPLOYER) {
            throw new RuntimeException("User không có quyền employer");
        }

        // Kiểm tra xem đã có profile employer chưa
        if (employerRepository.findByUserId(userId).isPresent()) {
            throw new RuntimeException("Employer profile đã tồn tại");
        }

        // Kiểm tra tên công ty đã tồn tại chưa
        if (employerRepository.existsByCompanyName(request.getCompanyName())) {
            throw new RuntimeException("Tên công ty đã tồn tại");
        }

        // Kiểm tra mã số thuế nếu có
        if (request.getTaxCode() != null && employerRepository.existsByTaxCode(request.getTaxCode())) {
            throw new RuntimeException("Mã số thuế đã tồn tại");
        }

        // Tạo employer profile mới
        Employer employer = new Employer();
        employer.setId(userId);
        employer.setUser(user);
        employer.setCompanyName(request.getCompanyName());
        employer.setCompanyDescription(request.getCompanyDescription());
        employer.setCompanyWebsite(request.getCompanyWebsite());
        employer.setCompanyLogo(request.getCompanyLogo());
        employer.setCompanyAddress(request.getCompanyAddress());
        employer.setCompanySize(request.getCompanySize());
        employer.setIndustry(request.getIndustry());
        employer.setTaxCode(request.getTaxCode());
        employer.setContactPhone(request.getContactPhone());
        employer.setSocialLinks(request.getSocialLinks());
        employer.setActive(true);
        employer.setVerified(false);

        try {
            Employer savedEmployer = employerRepository.save(employer);
            // Fetch the employer again with user eagerly loaded
            Employer loadedEmployer = employerRepository.findByUserIdWithUser(userId)
                    .orElseThrow(() -> new RuntimeException("Could not load saved employer"));
            return EmployerDTO.fromEntity(loadedEmployer);
        } catch (Exception e) {
            // If we get a concurrent modification exception, retry the operation
            if (e instanceof org.springframework.orm.ObjectOptimisticLockingFailureException) {
                // Wait a short time and retry
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
                return setupEmployerProfile(userId, request);
            }
            throw e;
        }
    }

    public EmployerDTO getEmployerProfile(Long userId) {
        Employer employer = employerRepository.findByUserIdWithUser(userId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy employer profile"));
        return EmployerDTO.fromEntity(employer);
    }

    @Transactional
    public EmployerDTO updateEmployerProfile(Long userId, EmployerSetupRequest request) {
        Employer employer = employerRepository.findByUserIdWithUser(userId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy employer profile"));

        // Kiểm tra tên công ty nếu thay đổi
        if (!employer.getCompanyName().equals(request.getCompanyName()) &&
            employerRepository.existsByCompanyName(request.getCompanyName())) {
            throw new RuntimeException("Tên công ty đã tồn tại");
        }

        // Kiểm tra mã số thuế nếu thay đổi
        if (request.getTaxCode() != null && !request.getTaxCode().equals(employer.getTaxCode()) &&
            employerRepository.existsByTaxCode(request.getTaxCode())) {
            throw new RuntimeException("Mã số thuế đã tồn tại");
        }

        employer.setCompanyName(request.getCompanyName());
        employer.setCompanyDescription(request.getCompanyDescription());
        employer.setCompanyWebsite(request.getCompanyWebsite());
        employer.setCompanyLogo(request.getCompanyLogo());
        employer.setCompanyAddress(request.getCompanyAddress());
        employer.setCompanySize(request.getCompanySize());
        employer.setIndustry(request.getIndustry());
        employer.setTaxCode(request.getTaxCode());
        employer.setContactPhone(request.getContactPhone());
        employer.setSocialLinks(request.getSocialLinks());

        Employer updatedEmployer = employerRepository.save(employer);
        // Fetch again with user eagerly loaded
        Employer loadedEmployer = employerRepository.findByUserIdWithUser(userId)
                .orElseThrow(() -> new RuntimeException("Could not load updated employer"));
        return EmployerDTO.fromEntity(loadedEmployer);
    }

    //find by employer ID
    public EmployerDTO findEmployerById(Long employerId) {
        Employer employer = employerRepository.findById(employerId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy employer với ID: " + employerId));
        return EmployerDTO.fromEntity(employer);
    }

    /**
     * Cập nhật thông tin employer
     * @param employerId ID của employer
     * @param request Thông tin cập nhật
     * @return EmployerDTO sau khi cập nhật
     */
    @Transactional
    public EmployerDTO updateEmployer(Long employerId, EmployerUpdateRequest request) {
        Employer employer = employerRepository.findById(employerId)
                .orElseThrow(() -> new EntityNotFoundException("Không tìm thấy employer với ID: " + employerId));

        // Kiểm tra tên công ty đã tồn tại chưa (nếu có thay đổi)
        if (!employer.getCompanyName().equals(request.getCompanyName()) &&
            employerRepository.existsByCompanyName(request.getCompanyName())) {
            throw new RuntimeException("Tên công ty đã tồn tại");
        }

        // Kiểm tra mã số thuế đã tồn tại chưa (nếu có thay đổi)
        if (request.getTaxCode() != null && !request.getTaxCode().equals(employer.getTaxCode()) &&
            employerRepository.existsByTaxCode(request.getTaxCode())) {
            throw new RuntimeException("Mã số thuế đã tồn tại");
        }

        // Cập nhật thông tin
        employer.setCompanyName(request.getCompanyName());
        employer.setCompanyDescription(request.getCompanyDescription());
        employer.setCompanyWebsite(request.getCompanyWebsite());
        employer.setCompanyLogo(request.getCompanyLogo());
        employer.setCompanyAddress(request.getCompanyAddress());
        employer.setCompanySize(request.getCompanySize());
        employer.setIndustry(request.getIndustry());
        employer.setTaxCode(request.getTaxCode());
        employer.setContactPhone(request.getContactPhone());
        employer.setSocialLinks(request.getSocialLinks());

        Employer updatedEmployer = employerRepository.save(employer);
        return convertToDTO(updatedEmployer);
    }

    /**
     * Lấy thông tin employer theo ID
     * @param employerId ID của employer
     * @return EmployerDTO
     */
    public EmployerDTO getEmployerById(Long employerId) {
        Employer employer = employerRepository.findById(employerId)
                .orElseThrow(() -> new EntityNotFoundException("Không tìm thấy employer với ID: " + employerId));
        return convertToDTO(employer);
    }

    /**
     * Lấy thông tin employer theo user ID
     * @param userId ID của user
     * @return EmployerDTO
     */
    public EmployerDTO getEmployerByUserId(Long userId) {
        Employer employer = employerRepository.findByUserId(userId)
                .orElseThrow(() -> new EntityNotFoundException("Không tìm thấy employer với user ID: " + userId));
        return convertToDTO(employer);
    }

    private EmployerDTO convertToDTO(Employer employer) {
            return EmployerDTO.builder()
                .id(employer.getId())
                .userId(employer.getUser().getId())
                .companyName(employer.getCompanyName())
                .companyDescription(employer.getCompanyDescription())
                .companyWebsite(employer.getCompanyWebsite())
                .companyLogo(employer.getCompanyLogo())
                .companyAddress(employer.getCompanyAddress())
                .companySize(employer.getCompanySize())
                .industry(employer.getIndustry())
                .taxCode(employer.getTaxCode())
                .contactPhone(employer.getContactPhone())
                .socialLinks(employer.getSocialLinks())
                .verified(employer.isVerified())
                .active(employer.isActive())
                .build();
    }

    /**
     * Kiểm tra xem một user có phải là employer hay không
     */
    public boolean isEmployer(Long userId) {
        return employerRepository.findByUserId(userId).isPresent();
    }

    /**
     * Lấy thông tin của employer hiện tại
     */
    public EmployerDTO getCurrentEmployer() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy user"));
        
        Employer employer = employerRepository.findByUserId(user.getId())
                .orElseThrow(() -> new RuntimeException("Không tìm thấy thông tin employer"));
                
        return EmployerDTO.fromEntity(employer);
    }
} 