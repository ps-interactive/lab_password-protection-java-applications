package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class SecurePasswordDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurePasswordDemoApplication.class, args);
        System.out.println("--- Secure Password Web Demo Running (Using BCrypt) ---");
        System.out.println("Register: POST /register {\"username\":\"user\",\"password\":\"pass\"}");
        System.out.println("Login:    POST /login {\"username\":\"user\",\"password\":\"pass\"}");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

class UserCredentials {
    private String username;
    private String password;
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

@RestController
class AuthController {
    private final LoginServiceSecure loginService;
    public AuthController(LoginServiceSecure loginService) { this.loginService = loginService; }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody UserCredentials credentials) {
        if (credentials == null || credentials.getUsername() == null || credentials.getPassword() == null ||
            credentials.getUsername().trim().isEmpty() || credentials.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body("Username and password cannot be empty.");
        }
        try {
            boolean registered = loginService.registerUser(credentials.getUsername(), credentials.getPassword());
            if (registered) {
                System.out.println("API: Registration request successful for '" + credentials.getUsername() + "'.");
                return ResponseEntity.status(HttpStatus.CREATED).body("User '" + credentials.getUsername() + "' registered successfully.");
            } else {
                 System.out.println("API: Registration conflict for existing user '" + credentials.getUsername() + "'.");
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Username '" + credentials.getUsername() + "' already exists.");
            }
        } catch (Exception e) {
            System.err.println("API: Error during registration for user '" + credentials.getUsername() + "': " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Registration failed due to an internal error.");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody UserCredentials credentials) {
         if (credentials == null || credentials.getUsername() == null || credentials.getPassword() == null) {
            return ResponseEntity.badRequest().body("Username and password required.");
        }
        System.out.println("\nAPI: Login request received for user: " + credentials.getUsername());
        boolean loggedIn = loginService.login(credentials.getUsername(), credentials.getPassword());

        if (loggedIn) {
            System.out.println("API: Login check successful for user: " + credentials.getUsername());
            return ResponseEntity.ok("Login successful for user '" + credentials.getUsername() + "'.");
        } else {
            System.out.println("API: Login check failed for user: " + credentials.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed: Invalid username or password.");
        }
    }
}


@Service
class LoginServiceSecure {

    private final Map<String, String> userCredentials = new ConcurrentHashMap<>();
    private final PasswordEncoder passwordEncoder;

    public LoginServiceSecure(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        System.out.println("LoginServiceSecure: Initialized with BCryptPasswordEncoder.");
    }

    public boolean registerUser(String username, String password) {
        String trimmedUsername = (username != null) ? username.trim() : null;
        System.out.println("\n--- Service: registerUser called ---");
        System.out.println("Service: Attempting registration for username: '" + trimmedUsername + "'");

        if (trimmedUsername == null || trimmedUsername.isEmpty() || password == null || password.isEmpty()) {
            System.err.println("Service: Registration failed - Username or password cannot be empty.");
            return false;
        }

        System.out.println("Service: Raw password received: '" + password + "'"); 
        System.out.println("Service: Preparing to hash password using BCrypt...");

        String hashedPassword = passwordEncoder.encode(password);

        System.out.println("Service: BCrypt hashing complete.");
        System.out.println("Service:   -> Raw Password: '" + password + "'");
        System.out.println("Service:   -> BCrypt Hash : '" + hashedPassword + "'");

        System.out.println("Service: Checking if username '" + trimmedUsername + "' already exists...");
        String previousValue = userCredentials.putIfAbsent(trimmedUsername, hashedPassword);

        if (previousValue == null) {
            System.out.println("Service: Username '" + trimmedUsername + "' did not exist. Added to storage.");
            System.out.println("Service: Registration successful for '" + trimmedUsername + "'.");
            return true; 
        } else {
            System.out.println("Service: Username '" + trimmedUsername + "' already exists. Registration failed.");
            System.out.println("Service:   -> Existing Hash in storage: '" + previousValue + "'");
            return false; 
        }
    }

    public boolean login(String username, String password) {
        String trimmedUsername = (username != null) ? username.trim() : null;
        System.out.println("\n--- Service: login called ---");
        System.out.println("Service: Attempting login for username: '" + trimmedUsername + "'");

        if (trimmedUsername == null || password == null) {
             System.out.println("Service: Login failed - Null username or password provided.");
             return false;
        }

        System.out.println("Service: Retrieving stored hash for username '" + trimmedUsername + "'...");
        String storedHash = userCredentials.get(trimmedUsername);

        if (storedHash == null) {
            System.out.println("Service: Login failed - User '" + trimmedUsername + "' not found in storage.");
            return false; 
        }
        System.out.println("Service: Found stored BCrypt hash: '" + storedHash + "'");

        System.out.println("Service:   -> Raw Password Received: '" + password + "'"); 
        System.out.println("Service:   -> Stored BCrypt Hash  : '" + storedHash + "'");

        boolean match = passwordEncoder.matches(password, storedHash);

        System.out.println("Service: Comparison result using passwordEncoder.matches(): " + (match ? "MATCH" : "NO MATCH"));

        if (match) {
             System.out.println("Service: Password is valid for user '" + trimmedUsername + "'. Login successful.");
        } else {
             System.out.println("Service: Password is invalid for user '" + trimmedUsername + "'. Login failed.");
        }
        return match;
    }
}
