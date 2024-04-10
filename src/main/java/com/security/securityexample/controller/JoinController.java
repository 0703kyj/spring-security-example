package com.security.securityexample.controller;

import com.security.securityexample.dto.JoinDto;
import com.security.securityexample.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(@RequestBody JoinDto joinDto) {

        joinService.join(joinDto);

        return "OK";
    }
}
