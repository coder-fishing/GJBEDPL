package org.example.goodjobbackend.repository;

import org.example.goodjobbackend.model.JobApplication;
import org.example.goodjobbackend.model.ApplicationStatus;
import org.example.goodjobbackend.model.Job;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.model.Employer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface JobApplicationRepository extends JpaRepository<JobApplication, Long> {
    List<JobApplication> findByJob(Job job);
    List<JobApplication> findByApplicant(User applicant);
    List<JobApplication> findByEmployer(Employer employer);
    List<JobApplication> findByJobAndApplicant(Job job, User applicant);
    List<JobApplication> findByEmployerAndEmployerViewedFalse(Employer employer);
    List<JobApplication> findByEmployerAndStatus(Employer employer, ApplicationStatus status);
    
    @Query("SELECT ja FROM JobApplication ja WHERE ja.applicant.id = :userId")
    List<JobApplication> findByApplicantId(@Param("userId") Long userId);
    
    @Query("SELECT ja FROM JobApplication ja WHERE ja.job.jobId = :jobId")
    List<JobApplication> findByJobId(@Param("jobId") Long jobId);
    
    @Query("SELECT ja FROM JobApplication ja WHERE ja.employer.id = :employerId")
    List<JobApplication> findByEmployerId(@Param("employerId") Long employerId);
    
    @Query("SELECT ja FROM JobApplication ja WHERE ja.job.jobId = :jobId AND ja.applicant.id = :applicantId")
    List<JobApplication> findByJobIdAndApplicantId(@Param("jobId") Long jobId, @Param("applicantId") Long applicantId);
} 