package com.medgenome.linc.login.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenRequest {
    private String refreshToken;
}
