package org.example.goodjobbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JobTitleLengthStats {
    private Integer titleLength; // Độ dài của tiêu đề
    private Long count;         // Số lượng job có độ dài này
} 