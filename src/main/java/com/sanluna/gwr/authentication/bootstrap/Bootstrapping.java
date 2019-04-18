package com.sanluna.gwr.authentication.bootstrap;

import com.sanluna.gwr.authentication.model.User;
import com.sanluna.gwr.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;


@Component
public class Bootstrapping {

    @Autowired
    private UserRepository repository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostConstruct
    public void init(){
        User user = new User();
        user.createNew("test");
        user.setUsername("test");
        user.setPassword(passwordEncoder.encode("test"));
        user.setRoles("Admin");
        user.setTenant("test.gwr.se");
        repository.save(user);
    }

}
