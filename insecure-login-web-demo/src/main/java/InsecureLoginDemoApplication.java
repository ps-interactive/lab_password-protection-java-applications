package com.insecureloginimplementation.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap; 

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class InsecureLoginDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(InsecureLoginDemoApplication.class, args);
        System.out.println("--- Insecure Password Handling Web Demo Running ---");
        System.out.println("Register: POST /register {\"username\":\"user\",\"password\":\"pass\"}");
        System.out.println("Login:    POST /login {\"username\":\"user\",\"password\":\"pass\"}");
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

    private final LoginServiceInsecure loginService;

    public AuthController(LoginServiceInsecure loginService) {
        this.loginService = loginService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody UserCredentials credentials) {
        if (credentials == null || credentials.getUsername() == null || credentials.getPassword() == null ||
            credentials.getUsername().trim().isEmpty() || credentials.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body("Username and password cannot be empty.");
        }
        try {
            boolean registered = loginService.registerUser(credentials.getUsername(), credentials.getPassword());
            if (registered) {
                System.out.println("API: Registered user '" + credentials.getUsername() + "'");
                return ResponseEntity.status(HttpStatus.CREATED).body("User '" + credentials.getUsername() + "' registered successfully.");
            } else {
                 System.out.println("API: Attempted to register existing user '" + credentials.getUsername() + "'");
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
        System.out.println("\nAPI: Attempting login for user: " + credentials.getUsername());
        boolean loggedIn = loginService.login(credentials.getUsername(), credentials.getPassword());

        if (loggedIn) {
            System.out.println("API: Login SUCCESSFUL for user: " + credentials.getUsername());
            return ResponseEntity.ok("Login successful for user '" + credentials.getUsername() + "'.");
        } else {
            System.out.println("API: Login FAILED for user: " + credentials.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed: Invalid username or password.");
        }
    }
}


@Service
class LoginServiceInsecure {

    private final Map<String, String> userCredentials = new ConcurrentHashMap<>();

    private String hashPassword(String password) {
        if (password == null) {
             System.err.println("Attempted to hash a null password.");
             throw new IllegalArgumentException("Password cannot be null.");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: MD5 Algorithm not found!");
            throw new RuntimeException("MD5 algorithm not found", e);
        }
    }

    public boolean registerUser(String username, String password) {
        String trimmedUsername = (username != null) ? username.trim() : null;
        if (trimmedUsername == null || trimmedUsername.isEmpty() || password == null || password.isEmpty()) {
            System.err.println("Registration failed: Username or password cannot be empty.");
            return false; 
        }

         String hashedPassword = hashPassword(password); 

         String previousValue = userCredentials.putIfAbsent(trimmedUsername, hashedPassword);

         if (previousValue == null) {
             System.out.println("Service: Registered user '" + trimmedUsername + "' with hash: " + hashedPassword);
             return true; 
         } else {
             System.out.println("Service: User '" + trimmedUsername + "' already exists.");
             return false; 
         }
    }

    public boolean login(String username, String password) {
        String trimmedUsername = (username != null) ? username.trim() : null;
        if (trimmedUsername == null || password == null) {
             System.out.println("Service: Login attempt with null username or password.");
             return false;
        }
        String storedHash = userCredentials.get(trimmedUsername);

        if (storedHash == null) {
            System.out.println("Service: User '" + trimmedUsername + "' not found during login attempt.");
            return false; 
        }

        String enteredPasswordHash;
        try {
            enteredPasswordHash = hashPassword(password);
        } catch (RuntimeException e) {
            System.err.println("Service: Could not hash entered password for user '" + trimmedUsername + "': " + e.getMessage());
            return false;
        }


        System.out.println("Service: Comparing Hashes for user '" + trimmedUsername + "'");
        System.out.println("  Stored Hash : " + storedHash);
        System.out.println("  Entered Hash: " + enteredPasswordHash);
        boolean match = storedHash.equals(enteredPasswordHash);

        if (match) {
             System.out.println("Service: Hashes match for user '" + trimmedUsername + "'.");
        } else {
             System.out.println("Service: Hashes DO NOT match for user '" + trimmedUsername + "'.");
        }
        return match;
    }
     public void printStoredHashes() {
        System.out.println("\n--- Current Stored Hashes ---");
        if (userCredentials.isEmpty()) {
            System.out.println("No users registered yet.");
            return;
        }
        userCredentials.forEach((username, hash) ->
            System.out.println("  User: " + username + ", Stored MD5 Hash: " + hash)
        );
         System.out.println("-----------------------------");
    }
}
