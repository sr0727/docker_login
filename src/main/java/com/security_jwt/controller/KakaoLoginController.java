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

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api")
public class KakaoLoginController {

    private final JwtUtil jwtUtil;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${kakao.client-id}")
    private String clientId;

    @Value("${kakao.client-secret}")
    private String clientSecret;

    @Value("${kakao.redirect-uri}")
    private String redirectUri;

    private final String KAKAO_AUTH_URL = "https://kauth.kakao.com/oauth/authorize";
    private final String KAKAO_TOKEN_URL = "https://kauth.kakao.com/oauth/token";
    private final String KAKAO_USERINFO_URL = "https://kapi.kakao.com/v2/user/me";

    // Step 1: 리다이렉트 to Kakao OAuth2 인증 페이지
    @GetMapping("/kakao")
    public ResponseEntity<?> redirectToKakaoLogin() {
        String authorizationUrl = UriComponentsBuilder.fromHttpUrl(KAKAO_AUTH_URL)
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("response_type", "code")
                .toUriString();

        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, authorizationUrl)
                .build();
    }

    // Step 2: 카카오 인증 후 전달된 code 처리
    @GetMapping("/login/oauth2/code/kakao")
    public ResponseEntity<?> handleKakaoCallback(@RequestParam String code,
                                                 @RequestHeader(value = "andriodApp", required = false) String app) {

        Boolean isApp=false;
        if(app!=null && !app.isEmpty()){
            isApp = app.equalsIgnoreCase("AndroidApp");
        }
        // Step 3: 토큰 요청
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String tokenRequestBody = "grant_type=authorization_code" +
                "&client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&redirect_uri=" + redirectUri +
                "&code=" + code;

        HttpEntity<String> tokenRequest = new HttpEntity<>(tokenRequestBody, tokenHeaders);

        ResponseEntity<Map> tokenResponse = restTemplate.exchange(
                KAKAO_TOKEN_URL,
                HttpMethod.POST,
                tokenRequest,
                Map.class
        );

        if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, "/login-error")
                    .build();
        }

        String accessToken = (String) tokenResponse.getBody().get("access_token");

        // Step 4: 사용자 정보 요청
        HttpHeaders userHeaders = new HttpHeaders();
        userHeaders.setBearerAuth(accessToken);

        HttpEntity<Void> userRequest = new HttpEntity<>(userHeaders);

        ResponseEntity<Map> userInfoResponse = restTemplate.exchange(
                KAKAO_USERINFO_URL,
                HttpMethod.GET,
                userRequest,
                Map.class
        );

        if (!userInfoResponse.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, "/login-error")
                    .build();
        }

        Map<String, Object> kakaoAccount = (Map<String, Object>) ((Map) userInfoResponse.getBody().get("kakao_account"));
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        String email = (String) kakaoAccount.get("email");
        String name = (String) profile.get("nickname");
        String role = "ROLE_ADMIN";

        // Step 5: JWT 생성 및 쿠키 전달
        String access = this.jwtUtil.createToken("access", name, role, 60*10*1000L);
        String refresh = this.jwtUtil.createToken("refresh", name, role, 24*60*60*1000L);


        if(isApp){
            Map<String, String> token = new HashMap<>();
            token.put("access_token", "Bearer "+access);
            token.put("refresh_token", refresh);

            return ResponseEntity.status(HttpStatus.OK).body(token);
        }

        ResponseCookie cookie = ResponseCookie.from("refresh", refresh) //최초 refresh토큰만 전달하여 다시 access토큰을 요청하도록 함
                .httpOnly(true)
                .secure(false) // 운영환경에서는 true
                .path("/")
                .maxAge(600)
                .sameSite("Lax")
                .build();

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, cookie.toString());
        responseHeaders.set(HttpHeaders.LOCATION, "/test");

        return ResponseEntity.status(HttpStatus.FOUND).headers(responseHeaders).build();
    }
}

