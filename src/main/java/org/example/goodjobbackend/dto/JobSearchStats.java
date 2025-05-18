package org.example.goodjobbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JobSearchStats {
    private String jobTitle;    // Tiêu đề công việc
    private Long count;         // Số lượng job có tiêu đề này
} 