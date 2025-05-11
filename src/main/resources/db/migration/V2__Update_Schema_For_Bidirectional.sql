-- Add missing columns and relationships
ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS processed_by bigint,
    ADD CONSTRAINT fk_jobs_processed_by FOREIGN KEY (processed_by) REFERENCES users(id);

-- Update notifications table
ALTER TABLE notifications
    RENAME COLUMN related_id TO related_application_id;

-- Add missing indexes for better performance
CREATE INDEX IF NOT EXISTS idx_job_applications_job_id ON job_applications(job_id);
CREATE INDEX IF NOT EXISTS idx_job_applications_applicant_id ON job_applications(applicant_id);
CREATE INDEX IF NOT EXISTS idx_job_applications_employer_id ON job_applications(employer_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_related_application_id ON notifications(related_application_id);
CREATE INDEX IF NOT EXISTS idx_jobs_employer_id ON jobs(employer_id);
CREATE INDEX IF NOT EXISTS idx_jobs_processed_by ON jobs(processed_by); 