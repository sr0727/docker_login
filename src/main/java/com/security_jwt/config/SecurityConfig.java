package com.security_jwt.config;

import com.security_jwt.component.CustomAccessDeniedHandler;
import com.security_jwt.component.CustomAuthenticationEntryPoint;
import com.security_jwt.jwt.JwtFilter;
import com.security_jwt.jwt.JwtLoginFilter;
import com.security_jwt.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final JwtUtil jwtUtil;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf->csrf.disable())
                .formLogin(formLogin->formLogin.disable())
                .httpBasic(httpBasic->httpBasic.disable())

                .authorizeHttpRequests(authorizeHttpRequests->{
                    authorizeHttpRequests.requestMatchers("/", "/api/join", "/api/login", "/api/reissue").permitAll();
                    authorizeHttpRequests.requestMatchers("/api/admin").hasRole("ADMIN");
                    authorizeHttpRequests.anyRequest().authenticated();
                })

                .cors(cors->cors.configurationSource(request -> {
                    CorsConfiguration corsConfiguration = new CorsConfiguration();
                    corsConfiguration.setAllowCredentials(true);
                    corsConfiguration.addAllowedHeader("*"); //클라이언트가 요청을 보낼때 보낼수 있는 헤더
                    corsConfiguration.setExposedHeaders(List.of("Authorization")); //서버가 응답을 보낼때 브라우저가 접근할수 있는 헤더
                    corsConfiguration.addAllowedMethod("*");
                    corsConfiguration.addAllowedOrigin("http://localhost");
                    corsConfiguration.addAllowedOrigin("http://3.37.198.79");
                    return corsConfiguration;
                }))

                .sessionManagement(session->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .addFilterBefore(new JwtFilter(jwtUtil), JwtLoginFilter.class)

                .addFilterAt(new JwtLoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class)

                .exceptionHandling(exception->{
            exception.authenticationEntryPoint(this.customAuthenticationEntryPoint);
            exception.accessDeniedHandler(this.customAccessDeniedHandler);
        });

        return http.build();
    }
}
