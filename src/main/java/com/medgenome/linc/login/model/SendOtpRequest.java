package com.medgenome.linc.login.model;

import lombok.Data;

@Data
public class SendOtpRequest {
    private String emailOrPhone;
    private String password;
}
