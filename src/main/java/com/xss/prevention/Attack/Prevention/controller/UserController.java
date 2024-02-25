package com.xss.prevention.Attack.Prevention.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xss.prevention.Attack.Prevention.dto.req.UserCreateRequest;
import com.xss.prevention.Attack.Prevention.dto.res.SuccessResponse;
import com.xss.prevention.Attack.Prevention.dto.res.ErrorResponse;
import com.xss.prevention.Attack.Prevention.model.User;
import com.xss.prevention.Attack.Prevention.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    UserService userService;

    @PostMapping
    public ResponseEntity<SuccessResponse> createUser(@RequestBody UserCreateRequest userCreateRequest) throws Exception {

        User user = userService.createNewUser(userCreateRequest);
        if (user == null) {
            ErrorResponse errorResponse = new ErrorResponse();
            errorResponse.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            errorResponse.setMessage("Unable to create user");
            ObjectMapper mapper = new ObjectMapper();
            throw new Exception(mapper.writeValueAsString(errorResponse));
        }
        SuccessResponse sr = new SuccessResponse();
        sr.setContent("success");
        sr.setMessage("user created");
        return new ResponseEntity<>(sr, HttpStatus.ACCEPTED);
    }

    @GetMapping("/{id}")
    public ResponseEntity<User> getUser(@PathVariable String id) throws Exception {
        User existingUser = userService.viewById(id);
        if (existingUser == null) {
            ErrorResponse errorResponse = new ErrorResponse();
            errorResponse.setStatus(HttpStatus.NO_CONTENT.value());
            errorResponse.setMessage("User not found");
            ObjectMapper mapper = new ObjectMapper();
            throw new Exception(mapper.writeValueAsString(errorResponse));
        }
        return new ResponseEntity<>(existingUser, HttpStatus.OK);
    }
}
