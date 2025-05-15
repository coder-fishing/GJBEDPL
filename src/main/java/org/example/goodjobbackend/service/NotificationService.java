package org.example.goodjobbackend.service;

import lombok.RequiredArgsConstructor;
import org.example.goodjobbackend.model.Notification;
import org.example.goodjobbackend.model.NotificationType;
import org.example.goodjobbackend.model.JobApplication;
import org.example.goodjobbackend.model.User;
import org.example.goodjobbackend.repository.NotificationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class NotificationService {
    private final NotificationRepository notificationRepository;

    public Notification createNotification(User user, String title, String content, 
                                        NotificationType type, JobApplication relatedApplication) {
        Notification notification = new Notification();
        notification.setUser(user);
        notification.setTitle(title);
        notification.setContent(content);
        notification.setType(type);
        notification.setRelatedApplication(relatedApplication);
        return notificationRepository.save(notification);
    }

    public List<Notification> getUserNotifications(Long userId) {
        return notificationRepository.findByUserIdOrderByCreatedAtDesc(userId);
    }

    public List<Notification> getUnreadNotifications(Long userId) {
        return notificationRepository.findByUserIdAndReadFalseOrderByCreatedAtDesc(userId);
    }

    public long getUnreadCount(Long userId) {
        return notificationRepository.countByUserIdAndReadFalse(userId);
    }

    @Transactional
    public void markAsRead(Long notificationId) {
        Notification notification = notificationRepository.findById(notificationId)
            .orElseThrow(() -> new RuntimeException("Không tìm thấy thông báo"));
        notification.setRead(true);
        notificationRepository.save(notification);
    }

    @Transactional
    public void markAllAsRead(Long userId) {
        List<Notification> unreadNotifications = getUnreadNotifications(userId);
        unreadNotifications.forEach(notification -> notification.setRead(true));
        notificationRepository.saveAll(unreadNotifications);
    }

    // Tạo thông báo khi có người ứng tuyển mới
    public Notification notifyNewApplication(User employer, String applicantName, String jobTitle, JobApplication application) {
        String title = "Ứng viên mới ứng tuyển";
        String content = applicantName + " đã ứng tuyển vào vị trí " + jobTitle;
        return createNotification(employer, title, content, NotificationType.NEW_APPLICATION, application);
    }

    // Tạo thông báo khi trạng thái ứng tuyển thay đổi
    public void notifyApplicationStatus(User applicant, String jobTitle, String status, JobApplication application) {
        String title = "Cập nhật trạng thái ứng tuyển";
        String content = "Đơn ứng tuyển của bạn vào vị trí " + jobTitle + " đã được " + status;
        createNotification(applicant, title, content, NotificationType.APPLICATION_STATUS, application);
    }

    // Tạo thông báo cho employer khi admin duyệt/từ chối bài đăng
    public Notification notifyJobStatusToEmployer(User employer, String jobTitle, boolean isApproved, JobApplication application) {
        String title = "Cập nhật trạng thái bài đăng";
        String content = "Bài đăng \"" + jobTitle + "\" của bạn đã được " + (isApproved ? "duyệt" : "từ chối");
        return createNotification(employer, title, content, NotificationType.JOB_STATUS, application);
    }
} 