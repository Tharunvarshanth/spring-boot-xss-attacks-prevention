package com.xss.prevention.Attack.Prevention.dto.req;

import lombok.Data;

@Data
public class UserCreateRequest {

    private String username;

    private String password;

    private String userRole;

    private String mobileNumber;

    private String email;
}
