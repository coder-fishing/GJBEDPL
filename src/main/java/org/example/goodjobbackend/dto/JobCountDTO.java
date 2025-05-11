package org.example.goodjobbackend.dto;

import lombok.Data;
import org.example.goodjobbackend.model.JobStatus;

@Data
public class JobCountDTO {
    private JobStatus status;
    private Long count;

    public JobCountDTO(JobStatus status, Long count) {
        this.status = status;
        this.count = count;
    }

    public JobStatus getStatus() {
        return status;
    }

    public void setStatus(JobStatus status) {
        this.status = status;
    }

    public Long getCount() {
        return count;
    }

    public void setCount(Long count) {
        this.count = count;
    }

}