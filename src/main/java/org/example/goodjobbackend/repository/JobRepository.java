package org.example.goodjobbackend.repository;

import org.example.goodjobbackend.dto.JobCountDTO;
import org.example.goodjobbackend.model.Job;
import org.example.goodjobbackend.model.JobStatus;
import org.example.goodjobbackend.model.Employer;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface JobRepository extends JpaRepository<Job, Long> {

    // Tìm kiếm với bộ lọc (keyword, location, salary range), mặc định status = APPROVED
    @Query("SELECT j FROM Job j WHERE " +
            "(:keyword IS NULL OR :keyword = '' OR " +
            "LOWER(j.title) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(j.description) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(j.requirement) LIKE LOWER(CONCAT('%', :keyword, '%'))) " +
            "AND (:location IS NULL OR :location = '' OR " +
            "LOWER(j.location) LIKE LOWER(CONCAT('%', :location, '%'))) " +
            "AND (:minSalary IS NULL OR j.salaryMin >= :minSalary) " +
            "AND (:maxSalary IS NULL OR j.salaryMax <= :maxSalary) " +
            "AND j.status = 'APPROVED'")
    Page<Job> searchWithFilters(
            @Param("keyword") String keyword,
            @Param("location") String location,
            @Param("minSalary") Double minSalary,
            @Param("maxSalary") Double maxSalary,
            Pageable pageable);

    // Tìm kiếm với bộ lọc và trạng thái bất kỳ
    @Query("SELECT j FROM Job j WHERE " +
            "(:keyword IS NULL OR :keyword = '' OR " +
            "LOWER(j.title) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(j.description) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(j.requirement) LIKE LOWER(CONCAT('%', :keyword, '%'))) " +
            "AND (:location IS NULL OR :location = '' OR " +
            "LOWER(j.location) LIKE LOWER(CONCAT('%', :location, '%'))) " +
            "AND (:minSalary IS NULL OR j.salaryMin >= :minSalary) " +
            "AND (:maxSalary IS NULL OR j.salaryMax <= :maxSalary) " +
            "AND j.status = :status")
    Page<Job> searchWithFiltersAndStatus(
            @Param("keyword") String keyword,
            @Param("location") String location,
            @Param("minSalary") Double minSalary,
            @Param("maxSalary") Double maxSalary,
            @Param("status") JobStatus status,
            Pageable pageable);

    // Lấy danh sách công việc theo employer (phân trang)
    Page<Job> findByEmployer(Employer employer, Pageable pageable);

    // Lấy danh sách công việc theo employer và status (phân trang)
    Page<Job> findByEmployerAndStatus(Employer employer,
                                      @Param("status") JobStatus status,
                                      Pageable pageable);

    // Lấy danh sách công việc theo status (phân trang)
    Page<Job> findByStatus(JobStatus status, Pageable pageable);

    // Lấy danh sách công việc theo status, sắp xếp theo postedAt giảm dần (phân trang)
    Page<Job> findByStatusOrderByPostedAtDesc(JobStatus status, Pageable pageable);

    // Lấy danh sách công việc theo employer (không phân trang)
    List<Job> findByEmployer(Employer employer);

    // Lấy danh sách công việc theo employer và status (không phân trang)
    List<Job> findByEmployerAndStatus(Employer employer,
                                      @Param("status") JobStatus status);

    // Lấy danh sách công việc theo status (không phân trang)
    List<Job> findByStatus(JobStatus status);

    // Lấy danh sách công việc theo status, sắp xếp theo postedAt giảm dần (không phân trang)
    List<Job> findByStatusOrderByPostedAtDesc(JobStatus status);

    // Lấy toàn bộ danh sách công việc có status = APPROVED
    @Query("SELECT j FROM Job j WHERE j.status = 'APPROVED'")
    List<Job> findAllApproved();

    // Lấy toàn bộ danh sách công việc có status = PENDING
    @Query("SELECT j FROM Job j WHERE j.status = 'PENDING'")
    List<Job> findAllPending();

    // Lấy toàn bộ danh sách công việc có status = REJECTED
    @Query("SELECT j FROM Job j WHERE j.status = 'REJECTED'")
    List<Job> findAllRejected();

    // Lấy toàn bộ danh sách công việc có status = DELETED
    @Query("SELECT j FROM Job j WHERE j.status = 'DELETED'")
    List<Job> findAllDeleted();

    @Modifying
    @Query("UPDATE Job j SET j.viewCount = j.viewCount + 1 WHERE j.jobId = :jobId")
    void incrementViewCount(@Param("jobId") Long jobId);

    @Modifying
    @Query("UPDATE Job j SET j.applyCount = j.applyCount + 1 WHERE j.jobId = :jobId")
    void incrementApplyCount(@Param("jobId") Long jobId);

    @Query("SELECT SUM(j.viewCount) FROM Job j")
    Long getAllView();

    @Query("SELECT SUM(j.applyCount) FROM Job j")
    Long getAllApply();

    @Query("SELECT j.status, COUNT(j) FROM Job j GROUP BY j.status")
    List<Object[]> countJobsByStatus();

    @Query("SELECT j.title as jobTitle, COUNT(j) as count " +
           "FROM Job j " +
           "WHERE j.title LIKE %:keyword% " +
           "GROUP BY j.title " +
           "ORDER BY count DESC")
    List<Object[]> countJobsByKeyword(@Param("keyword") String keyword);
}