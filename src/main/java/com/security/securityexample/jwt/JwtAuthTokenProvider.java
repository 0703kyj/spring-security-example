package com.security.securityexample.jwt;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthTokenProvider {
    private final SecretKey secretKey;

    public JwtAuthTokenProvider(@Value("${app.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    //유저 이름 검증을 위한 추출 로직
    public String getUsername(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    //역할 검증을 위한 추출 로직
    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    //만료 시간 검증을 위한 추출 로직
    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createToken(String username, String role, Long expiredMs) {

        long now = System.currentTimeMillis();

        return Jwts.builder()
                .claim("username", username) //Payload 부분에 넣을 수 있는 값
                .claim("role", role)
                .issuedAt(new Date(now)) //현재 발행 시간
                .expiration(new Date(now + expiredMs)) //토큰 만료 시간
                .signWith(secretKey)
                .compact();
    }
}
