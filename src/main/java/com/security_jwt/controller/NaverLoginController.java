package com.security_jwt.controller;
import com.security_jwt.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api")
public class NaverLoginController {

    private final JwtUtil jwtUtil;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${naver.client-id}")
    private String clientId;

    @Value("${naver.client-secret}")
    private String clientSecret;

    @Value("${naver.redirect-uri}")
    private String redirectUri;

    private final String NAVER_AUTH_BASE = "https://nid.naver.com/oauth2.0/authorize";
    private final String NAVER_TOKEN_URL = "https://nid.naver.com/oauth2.0/token";
    private final String NAVER_USERINFO_URL = "https://openapi.naver.com/v1/nid/me";

    // Step 1: 리다이렉트 to Naver OAuth2 인증 페이지
    @GetMapping("/naver")
    public ResponseEntity<?> redirectToNaverLogin() {
        String state = UUID.randomUUID().toString(); // CSRF 방지를 위한 state 파라미터
        String authorizationUrl = UriComponentsBuilder.fromHttpUrl(NAVER_AUTH_BASE)
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", redirectUri)
                .queryParam("state", state) //CSRF공격을 방지하기 위한 인증 요청의 고유 식별자
                .build()
                .toUriString();

        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, authorizationUrl)
                .build();
    }

    // Step 2: Naver가 전달한 code, state를 처리
    @GetMapping("/login/oauth2/code/naver")
    public ResponseEntity<?> handleNaverCallback(@RequestParam Map<String, String> params,
//                                                 @RequestHeader Map<String, String> headers,
                                                 @RequestHeader (value = "andriodApp", required = false) String app) {
        String code = params.get("code");
        String state = params.get("state");

        Boolean isApp=false;

        if(app!=null && !app.isEmpty()){
            isApp = app.equalsIgnoreCase("AndroidApp");
        }

        // Step 3: code로 access token 요청
        String tokenRequestUrl = UriComponentsBuilder.fromHttpUrl(NAVER_TOKEN_URL)
                .queryParam("grant_type", "authorization_code")
                .queryParam("client_id", clientId)
                .queryParam("client_secret", clientSecret)
                .queryParam("code", code)
                .queryParam("state", state)
                .toUriString();

        ResponseEntity<Map> tokenResponse = restTemplate.exchange(
                tokenRequestUrl,
                HttpMethod.GET,
                null,
                Map.class
        );

        if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("네이버 access token 발급 실패");
        }

        String accessToken = (String) tokenResponse.getBody().get("access_token");

        // Step 4: 사용자 정보 조회
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> userRequest = new HttpEntity<>(headers);
        ResponseEntity<Map> userInfoResponse = restTemplate.exchange(
                NAVER_USERINFO_URL,
                HttpMethod.GET,
                userRequest,
                Map.class
        );

        if (!userInfoResponse.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, "/login-error")
                    .build();
        }

        Map<String, Object> responseBody = userInfoResponse.getBody();
        Map<String, Object> userInfo = (Map<String, Object>) responseBody.get("response");

        String name = (String) userInfo.get("name");
        String email = (String) userInfo.get("email");
        String role = "ROLE_ADMIN";

        // Step 5: JWT 생성 + 쿠키 설정 + 리다이렉트
        String access = this.jwtUtil.createToken("access", name, role, 60*10*1000L);
        String refresh = this.jwtUtil.createToken("refresh", name, role, 24*60*60*1000L);


        if(isApp){
            Map<String, String> token = new HashMap<>();
            token.put("access_token", "Bearer "+access);
            token.put("refresh_token", refresh);

            return ResponseEntity.status(HttpStatus.OK).body(token);
        }

        ResponseCookie cookie = ResponseCookie.from("refresh", refresh)
                .httpOnly(true)
                .secure(false) // 운영 시 true
                .path("/")
                .maxAge(600)
                .sameSite("Lax")
                .build();

        String redirectUrl = "/test"; // 리다이렉트 대상 URL

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, cookie.toString());
        responseHeaders.set(HttpHeaders.LOCATION, redirectUrl);

        return ResponseEntity.status(HttpStatus.FOUND).headers(responseHeaders).build();
    }
}
