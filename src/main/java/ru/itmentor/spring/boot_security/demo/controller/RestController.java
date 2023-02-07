package ru.itmentor.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.itmentor.spring.boot_security.demo.model.Role;
import ru.itmentor.spring.boot_security.demo.model.User;
import ru.itmentor.spring.boot_security.demo.service.RoleService;
import ru.itmentor.spring.boot_security.demo.service.UserService;

import java.util.List;

@org.springframework.web.bind.annotation.RestController
@CrossOrigin
@RequestMapping(value = "/admin/users", produces = MediaType.APPLICATION_JSON_VALUE)
public class RestController {

    private final UserService userService;

    private final RoleService roleService;

    @Autowired
    public RestController(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping()
    public ResponseEntity<List<User>>  allUsers() {

        return ResponseEntity.ok(userService.showAllUsers());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getUser(@PathVariable int id) {
        try {
            User user = userService.showUser(id);
            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public User addNewUser(@RequestBody User user) {
        userService.saveUser(user);
        return userService.showUser(user.getId());
    }

    @PutMapping(value = "/{id}", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public User updateUser(@RequestBody User user, @PathVariable("id") int id) {
        userService.update(id, user);
        return user;
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteUser(@PathVariable int id) {
        userService.delete(id);
    }


    @GetMapping("/roles")
    public ResponseEntity<List<Role>> getRoles() {
        return new ResponseEntity<>(roleService.getRoleList(), HttpStatus.OK);
    }
}
