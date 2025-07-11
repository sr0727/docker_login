package com.security_jwt.component;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("error", "Unauthorized");
        responseData.put("message", "먼저 로그인후 시도해주세요");

        ObjectMapper mapper = new ObjectMapper();
        String jsonmessage= mapper.writeValueAsString(responseData);
        response.setContentType("application/json");
        response.setStatus(401);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(jsonmessage);
    }
}
