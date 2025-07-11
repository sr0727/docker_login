package com.security_jwt.controller;


import com.security_jwt.data.dto.AuthDTO;
import com.security_jwt.data.entity.AuthEntity;
import com.security_jwt.data.repository.AuthRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api")
public class AuthController {
    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping(value = "/join")
    public ResponseEntity<String> join(@RequestBody AuthDTO authDTO) {
        if(this.authRepository.existsByUsername(authDTO.getUsername())) {
            return new ResponseEntity<>("Username already exists", HttpStatus.CONFLICT);
        }
        AuthEntity authEntity = AuthEntity.builder()
                .username(authDTO.getUsername())
                .password(this.passwordEncoder.encode(authDTO.getPassword()))
                .role("ROLE_USER").build();
        this.authRepository.save(authEntity);
        return ResponseEntity.status(HttpStatus.CREATED).body("가입성공");
    }

    @GetMapping(value="/admin")
    public ResponseEntity<String> admin() {

        return ResponseEntity.status(HttpStatus.OK).body("관리자입니다.");
    }
}
