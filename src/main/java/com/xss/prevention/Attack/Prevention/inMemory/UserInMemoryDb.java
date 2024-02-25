package com.xss.prevention.Attack.Prevention.inMemory;

import com.xss.prevention.Attack.Prevention.model.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserInMemoryDb {

    private static List<User> users;

    public UserInMemoryDb() {
        users = new ArrayList<>();
    }

    public void addUser(User user) {
        users.add(user);

    }

    public User getUserById(String id) {

        return users.stream()
                .filter(user -> user.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    public Integer getNoOfUsers(){
        return users.size();
    }
}
