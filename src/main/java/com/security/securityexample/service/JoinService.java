package com.security.securityexample.service;

import com.security.securityexample.dto.JoinDto;
import com.security.securityexample.entity.UserEntity;
import com.security.securityexample.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    public void join(JoinDto joinDto) {

        Boolean isExist = userRepository.existsByUsername(joinDto.username());

        if (Boolean.TRUE.equals(isExist)) {
            return;
        }
        UserEntity userEntity = UserEntity.builder()
                .username(joinDto.username())
                .password(bCryptPasswordEncoder.encode(joinDto.password()))
                .role("ROLE_ADMIN")
                        .build();

        userRepository.save(userEntity);
    }
}
