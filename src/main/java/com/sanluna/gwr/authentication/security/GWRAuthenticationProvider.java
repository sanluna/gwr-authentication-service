package com.sanluna.gwr.authentication.security;

import com.sanluna.gwr.authentication.model.User;
import com.sanluna.gwr.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import sanluna.gwr.security.principal.GWRPrincipal;

import java.util.Collections;

public class GWRAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserRepository repository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = removeTenant(authentication.getName());
        String tenant = getTenant(authentication.getName());
        String password = authentication.getCredentials().toString();
        User user = repository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("user with username: " + username + " was not found!");
        }
        if (passwordEncoder.matches(password, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(principalBuilder(user), password, Collections.emptyList());
        } else {
            throw new BadCredentialsException("Authentication fail!");
        }
    }

    private String removeTenant(String name) {
        return name.split(":-:")[1];
    }

    private String getTenant(String name) {
        return name.split(":-:")[0];
    }

    private Object principalBuilder(User user) {

        return new GWRPrincipal(user.getId(), user.getUsername(), user.getRoles(), user.getTenant());

    }

    public boolean supports(Class<?> authClass) {
        return authClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
