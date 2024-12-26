package com.ust.SpringSecurity.repository;

import com.ust.SpringSecurity.model.OtpEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OtpRepository extends JpaRepository<OtpEntity, Long> {
    OtpEntity findByEmail(String email); // Find OTP by email
}
