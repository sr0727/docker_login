package com.security_jwt.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
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
public class GoogleLoginController {
    private final JwtUtil jwtUtil;

    @Value("${google.client-id}")
    private String clientId;

    @Value("${google.client-secret}")
    private String clientSecret;

    @Value("${google.redirect-uri}")
    private String redirectUri;

    private final RestTemplate restTemplate=new RestTemplate();
    // RestTemplate : 다른 서버(API)에 **HTTP 요청(GET, POST, PUT, DELETE 등)**을 보내고,
    //응답을 받아오는 데 사용
    // exchange() :	모든 HTTP 메서드, 헤더, 바디를 자유롭게 구성해 요청하는 가장 유연한 방식


    // Step 1: Redirect to Google OAuth2 authorization URL
    @GetMapping(value = "/google")
    public ResponseEntity<?> googleLogin() {
        String authorizationUrl = UriComponentsBuilder.fromUriString("https://accounts.google.com/o/oauth2/v2/auth")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("response_type", "code")
                .queryParam("scope", "email profile")
                .toUriString();

        return ResponseEntity.status(HttpStatus.FOUND).header("Location", authorizationUrl).build();
    }

    // Step 2: Handle redirect with authorization code from the social auth server
    @GetMapping(value = "/login/oauth2/code/google")
    public ResponseEntity<?> googleLoginCode(@RequestParam Map<String, String> params,
                                             @RequestHeader (value = "andriodApp", required = false) String app) throws JsonProcessingException {
        Boolean isApp=false;
        if(app!=null && !app.isEmpty()){
            isApp = app.equalsIgnoreCase("AndroidApp");
        }

        String code = params.get("code");

        // Step 3: Exchange authorization code for access token
        String tokenUrl = "https://oauth2.googleapis.com/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED); //application/x-www-form-urlencode

        String body = "grant_type=authorization_code" +
                "&client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&code=" + code +
                "&redirect_uri=" + redirectUri;

        HttpEntity<String> request = new HttpEntity<>(body, headers);
        //HttpEntity: HTTP 요청에 사용할 본문과 헤더를 함께 포장하는 객체

        ResponseEntity<Map> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, Map.class);
        //Map.class: 응답 결과를 JSON → Map 형태로 자동 변환함
        //소셜 인증 서버에 POST 요청을 보내고 응답을 Map으로 받음
        //(access_token, refresh_token, expires_in 등 포함)

        if(!response.getStatusCode().is2xxSuccessful()) { //응답의 HTTP 상태 코드가 2xx (성공) 범위가 아니라면,
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, "/login-error")
                    .build();
        }


        // Step 4: Use access token to get user information
        String accessToken = response.getBody().get("access_token").toString();

        String userInfoUrl = "https://www.googleapis.com/oauth2/v2/userinfo";

        HttpHeaders userHeaders = new HttpHeaders();
        userHeaders.setBearerAuth(accessToken);

        HttpEntity<Void> userRequest = new HttpEntity<>(userHeaders);

        ResponseEntity<Map> userInfoResponse = restTemplate.exchange(userInfoUrl, HttpMethod.GET, userRequest, Map.class);

        if(!userInfoResponse.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, "/login-error")
                    .build();
        }

        Map<String, Object> userInfo = userInfoResponse.getBody();
        String email = (String) userInfo.get("email");
        String name = (String) userInfo.get("name");
        String role = "ROLE_ADMIN";

        String acessToken = this.jwtUtil.createToken("access", name, role, 60*10*1000L);
        String refreshToken = this.jwtUtil.createToken("refresh", name, role, 24*60*60*1000L);


        if(isApp){
            Map<String, String> token = new HashMap<>();
            token.put("access_token", "Bearer "+accessToken);
            token.put("refresh_token", refreshToken);

            return ResponseEntity.status(HttpStatus.OK).body(token);
        }

              //  ResponseCookie로 쿠키 생성
        ResponseCookie cookie = ResponseCookie.from("refresh", refreshToken)
                .httpOnly(true)             // XSS 방지
                .secure(false)             // HTTPS 환경이면 true
                .path("/")
                .maxAge(60 * 10)           // 10분
                .sameSite("Lax")           // 옵션: Lax 또는 Strict 또는 None  PO
                //쿠키가 다른 출처(origin)로부터의 요청에 포함될 수 있는지 여부를 제어
                // get요청에는 쿠키가 포함되나 post요청에는 쿠키를 포함시키지 않음 (SecurityConfig에서 출처를 허용해 주었어도 post요청은 막힘
                .build();

        //브라우저는 302 응답 시 Location만 보고 리디렉트하고,
        //Authorization 헤더 등 나머지 헤더/바디는 무시
        //따라서 refresh token만 전달하고 Access token은 따로 전달하는 것이 보안상 좋음

        String redirectUrl = "/test"; // 리다이렉트 대상 URL

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, cookie.toString());
        responseHeaders.set(HttpHeaders.LOCATION, redirectUrl);

        return ResponseEntity.status(HttpStatus.FOUND).headers(responseHeaders).build();
    }
}
