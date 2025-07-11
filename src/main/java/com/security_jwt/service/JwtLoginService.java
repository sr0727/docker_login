package com.security_jwt.service;

import com.security_jwt.data.entity.AuthEntity;
import com.security_jwt.data.repository.AuthRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JwtLoginService implements UserDetailsService {
    private final AuthRepository authRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthEntity authEntity = this.authRepository.findByUsername(username);
        if(authEntity == null) {
            throw new UsernameNotFoundException("User not found" + username);
        }
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority(authEntity.getRole()));
        return new User(authEntity.getUsername(), authEntity.getPassword(), grantedAuthorities);
    }
}
