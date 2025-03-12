package com.medgenome.linc.login.model;

import lombok.Data;

@Data
public class ForgotPasswordRequest {
    private String emailOrPhone;
}
