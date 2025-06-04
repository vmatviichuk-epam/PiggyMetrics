package com.piggymetrics.auth.controller;

import com.piggymetrics.auth.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @PostMapping("/token")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            String jwt = jwtService.generateJwtToken(authentication);

            Map<String, Object> response = new HashMap<>();
            response.put("access_token", jwt);
            response.put("token_type", "Bearer");
            response.put("expires_in", 86400); // 24 hours

            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "invalid_grant");
            error.put("error_description", "Bad credentials");
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/client-token")
    public ResponseEntity<?> authenticateClient(@RequestBody ClientTokenRequest clientRequest) {
        // For service-to-service authentication
        // In a real implementation, you'd validate the client credentials
        String jwt = jwtService.generateJwtToken(
                clientRequest.getClientId(),
                clientRequest.getClientId(),
                "server"
        );

        Map<String, Object> response = new HashMap<>();
        response.put("access_token", jwt);
        response.put("token_type", "Bearer");
        response.put("expires_in", 86400);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestBody TokenValidationRequest request) {
        if (jwtService.validateJwtToken(request.getToken())) {
            try {
                String username = jwtService.getUsernameFromJwtToken(request.getToken());
                Map<String, Object> response = new HashMap<>();
                response.put("user", username);
                response.put("active", true);
                return ResponseEntity.ok(response);
            } catch (Exception e) {
                return ResponseEntity.badRequest().body(Map.of("active", false));
            }
        } else {
            return ResponseEntity.badRequest().body(Map.of("active", false));
        }
    }

    // Request DTOs
    public static class LoginRequest {
        private String username;
        private String password;

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class ClientTokenRequest {
        private String clientId;
        private String clientSecret;

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    }

    public static class TokenValidationRequest {
        private String token;

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }
} 