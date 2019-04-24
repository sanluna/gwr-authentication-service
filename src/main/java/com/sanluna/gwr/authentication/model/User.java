package com.sanluna.gwr.authentication.model;

import com.sanluna.commons.model.BaseDTO;
import com.sanluna.commons.model.entity.BaseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class User extends BaseDTO<User> implements UserDetails {

    private String username;
    private String password;
    private String roles;

    public String getUsername() {
        return username;
    }

    public User setUsername(String username) {
        this.username = username;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public User setPassword(String password) {
        this.password = password;
        return this;
    }

    public String getRoles() {
        return roles;
    }

    public User setRoles(String roles) {
        this.roles = roles;
        return this;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        ArrayList<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();
        if (this.roles == null) {
            return null;
        }
        for (String x : this.roles.split(",")) {
            grantedAuthorities.add(new SimpleGrantedAuthority(x));
        }
        return grantedAuthorities;
    }

    public boolean isAccountNonExpired() {
        return isEnabled();
    }

    public boolean isAccountNonLocked() {
        return isEnabled();
    }

    public boolean isCredentialsNonExpired() {
        return isEnabled();
    }

    public boolean isEnabled() {
        return isActive();
    }

    @Override
    public <T1 extends BaseEntity<T1>> T1 convertToEntity() {
        return null;
    }
}
