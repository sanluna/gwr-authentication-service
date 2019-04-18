package com.sanluna.gwr.authentication.filter;

import com.sanluna.gwr.authentication.security.GWRAuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthFilter extends UsernamePasswordAuthenticationFilter {

    private final GWRAuthenticationProvider authenticationProvider;

    public AuthFilter(GWRAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authenticationRequest = getRequest(request);
        setDetails(request, authenticationRequest);

        return authenticationProvider.authenticate(authenticationRequest);
    }

    private UsernamePasswordAuthenticationToken getRequest(HttpServletRequest request) {

        String username = obtainUsername(request);
        String password = obtainPassword(request);
        String tenant = request.getServerName();
        System.out.println(tenant);

        String usernameWithTenant = tenant + ":-:" + username;
        System.out.println(usernameWithTenant);

        return new UsernamePasswordAuthenticationToken(usernameWithTenant,password);

    }
}
