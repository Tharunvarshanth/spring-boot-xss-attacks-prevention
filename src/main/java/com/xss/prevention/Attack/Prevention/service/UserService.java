package com.xss.prevention.Attack.Prevention.service;

import com.xss.prevention.Attack.Prevention.dto.req.UserCreateRequest;
import com.xss.prevention.Attack.Prevention.inMemory.UserInMemoryDb;
import com.xss.prevention.Attack.Prevention.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    UserInMemoryDb userInMemoryDb;

    public User createNewUser(UserCreateRequest ucr){
        Integer size=userInMemoryDb.getNoOfUsers();
        User user = new User();
        user.setEmail(ucr.getEmail());
        user.setId("u"+(size+1));
        user.setUserRole(ucr.getUserRole());
        user.setPassword(ucr.getPassword());
        user.setUsername(ucr.getUsername());
        user.setMobileNumber(ucr.getMobileNumber());
        userInMemoryDb.addUser(user);
        System.out.println(user.getId());
        return user;
    }

    public User viewById(String id){
        return userInMemoryDb.getUserById(id);
    }
}
