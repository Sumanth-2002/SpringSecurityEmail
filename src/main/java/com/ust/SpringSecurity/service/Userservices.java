package com.ust.SpringSecurity.service;


import com.ust.SpringSecurity.model.OtpEntity;
import com.ust.SpringSecurity.model.UserInfo;
import com.ust.SpringSecurity.repository.OtpRepository;
import com.ust.SpringSecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class Userservices {
    @Autowired
    private UserRepository repo;
    private final BCryptPasswordEncoder passwordEncoderr = new BCryptPasswordEncoder();

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private OtpRepository otpRepository;

    public String addUser(UserInfo userInfo) {
        userInfo.setPassword(passwordEncoder.encode(userInfo.getPassword()));
        repo.save(userInfo);
        return "user added to system ";
    }
    public UserInfo getUserByEmail(String email) {
        return repo.findByEmail(email).orElse(null);
    }

    public String hashOtp(String otp) {
        return passwordEncoder.encode(otp);
    }

    public void saveOtp(String email, String hashedOtp) {
        OtpEntity otpEntity = new OtpEntity(email, hashedOtp, LocalDateTime.now().plusMinutes(5)); // 5-min expiration
        otpRepository.save(otpEntity);
    }

    public boolean validateOtp(String email, String otp) {
        OtpEntity otpEntity = otpRepository.findByEmail(email);
        if (otpEntity == null || !passwordEncoder.matches(otp, otpEntity.getOtp())) {
            return false; // OTP mismatch
        }
        if (otpEntity.getExpiryTime().isBefore(LocalDateTime.now())) {
            return false; // OTP expired
        }
        otpRepository.delete(otpEntity); // Invalidate OTP after use
        return true;
    }

    public void updatePassword(String email, String newPassword) {
        UserInfo user = repo.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
        user.setPassword(passwordEncoder.encode(newPassword));
        repo.save(user);
    }
}