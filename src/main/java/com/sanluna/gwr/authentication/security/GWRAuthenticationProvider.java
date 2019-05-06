package com.sanluna.gwr.authentication.security;

import com.sanluna.clients.memberclient.MemberClient;
import com.sanluna.clients.memberclient.model.MemberDTO;
import com.sanluna.gwr.authentication.model.User;
import com.sanluna.multitenancy.multitenancy.TenantContext;
import com.sanluna.security.principal.GWRPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class GWRAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private MemberClient client;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = removeTenant(authentication.getName());
        String tenant = getTenant(authentication.getName());
        TenantContext.setCurrentTenant(tenant);
        String password = authentication.getCredentials().toString();
        MemberDTO member = client.getMember(username);
        if (member == null) {
            throw new UsernameNotFoundException("user with username: " + username + " was not found!");
        }
        User user = new User()
                .setRoles(member.getRoles())
                .setPassword(member.getPassword())
                .setUsername(member.getUsername());
        user.setId(member.getId());
        if (passwordEncoder.matches(password, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(principalBuilder(user), password, user.getAuthorities());
        } else {
            throw new BadCredentialsException("Authentication fail!");
        }
    }

    private String removeTenant(String name) {
        try {
            return name.substring(name.indexOf(":") + 1);
        } catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("array out of bounds");
            return "anon";
        }
    }

    private String getTenant(String name) {
        try {
            return name.substring(0, name.indexOf(":"));
        } catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("array out of bounds");
            return "tenant";
        }
    }

    private Object principalBuilder(User user) {

        return new GWRPrincipal(user.getId(), user.getUsername(), user.getRoles(), TenantContext.getCurrentTenant());

    }

    public boolean supports(Class<?> authClass) {
        return authClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
