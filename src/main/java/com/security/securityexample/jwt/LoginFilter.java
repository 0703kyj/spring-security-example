package com.security.securityexample.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 username과 password 추출함
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        //spring security에서 username과 password를 검증하기위한 Token(DTO)
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                username, password, null);

        //토근 검증을 위해 authenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
            HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {
    }
}
