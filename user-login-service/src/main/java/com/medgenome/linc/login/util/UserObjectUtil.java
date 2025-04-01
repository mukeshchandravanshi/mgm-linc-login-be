package com.medgenome.linc.login.util;

import com.medgenome.linc.login.model.User;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

@Component
public class UserObjectUtil {


    private static final ConcurrentHashMap<String, User> tempUserStore = new ConcurrentHashMap<>();

    // Save User
    public static void saveUser(String emailOrPhone, User user) {
        tempUserStore.put(emailOrPhone, user);
    }

    // Get User
    public static User getUser(String emailOrPhone) {
        return tempUserStore.get(emailOrPhone);
    }

    // Remove User
    public static void removeUser(String emailOrPhone) {
        tempUserStore.remove(emailOrPhone);
    }
}


