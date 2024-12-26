package com.ust.SpringSecurity.controller;


import com.ust.SpringSecurity.dto.AuthRequest;
import com.ust.SpringSecurity.dto.ResetPasswordRequest;
import com.ust.SpringSecurity.model.Event;
import com.ust.SpringSecurity.model.UserInfo;
import com.ust.SpringSecurity.repository.UserRepository;
import com.ust.SpringSecurity.service.EmailService;
import com.ust.SpringSecurity.service.EventService;
import com.ust.SpringSecurity.service.JwtService;
import com.ust.SpringSecurity.service.Userservices;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api")
public class UserController {
    @Autowired
    private Userservices service;
    @Autowired
    private EventService eventService;
    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepository repo;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private EmailService emailService; // Custom service to send emails

    // To track rate-limiting for OTP requests
    private final ConcurrentHashMap<String, LocalDateTime> requestTracker = new ConcurrentHashMap<>();

    // Forgot Password - Send OTP
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody String email) {
        // Rate-limiting: Allow 1 request per minute
        LocalDateTime lastRequestTime = requestTracker.get(email);
        if (lastRequestTime != null && lastRequestTime.plusMinutes(1).isAfter(LocalDateTime.now())) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("Too many requests. Try again later.");
        }
        requestTracker.put(email, LocalDateTime.now());


        UserInfo user = service.getUserByEmail(email);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Email not registered");
        }

        // Generate OTP
        String otp = String.valueOf((int) (Math.random() * 900000) + 100000); // Random 6-digit OTP
        String hashedOtp = service.hashOtp(otp); // Hash OTP for security
        service.saveOtp(email, hashedOtp); // Save hashed OTP in DB

        // Send OTP via email
        emailService.sendEmail(email, "Your OTP Code", "Your OTP is: " + otp);

        return ResponseEntity.ok("OTP sent to your email");
    }
//    @GetMapping("/user/{email}")
//    public ResponseEntity<?> getUserByEmail(@PathVariable String email) {
//        Optional<UserInfo> user = repo.findByEmail(email);
//        if (user.isPresent()) {
//            return ResponseEntity.ok(user.get());
//        } else {
//            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Email not registered");
//        }
//    }

    // Reset Password
    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        String email = request.getEmail();
        String otp = request.getOtp();
        String newPassword = request.getNewPassword();

        // Validate OTP
        boolean isOtpValid = service.validateOtp(email, otp);
        if (!isOtpValid) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid or expired OTP");
        }

        // Update password
        service.updatePassword(email, newPassword);

        return ResponseEntity.ok("Password reset successfully");
    }

    @PostMapping("/adduser")
    public String addNewUser(@RequestBody  UserInfo user){
        return service.addUser(user);
    }
    @PostMapping("/addEvent")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Event addEvent(@RequestBody Event event){
        return eventService.addEvent(event);
    }

    @GetMapping("/getAllEvents")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public List<Event> getalljobs(){
        return eventService.getAllEvents();
    }

    //login endpoint
    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(authRequest.getUsername());
        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }


    }



}