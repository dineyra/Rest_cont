package ru.itmentor.spring.boot_security.demo.service;


import ru.itmentor.spring.boot_security.demo.model.User;

import java.util.List;

public interface UserService {
    List<User> showAllUsers ();
    User showUser (int id);
    void saveUser(User user);
    void update (int id, User updatedUser);
    void delete (int id);
}