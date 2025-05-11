package org.example.goodjobbackend.dto;

import lombok.Data;
import org.example.goodjobbackend.model.Job;

import java.util.List;

@Data
public class JobResponse {
    private List<Job> jobs;
    private int page;
    private int size;
    private long totalElements;
    private int totalPages;
    private boolean hasNext;
    private boolean hasPrevious;

    public JobResponse(List<Job> jobs, int page, int size, long totalElements) {
        this.jobs = jobs;
        this.page = page;
        this.size = size;
        this.totalElements = totalElements;
        this.totalPages = (int) Math.ceil((double) totalElements / size);
        this.hasNext = page < totalPages - 1;
        this.hasPrevious = page > 0;
    }
}