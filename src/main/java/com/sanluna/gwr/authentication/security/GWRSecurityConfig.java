package com.sanluna.gwr.authentication.security;

import com.sanluna.gwr.authentication.filter.AuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class GWRSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private GWRAuthenticationProvider authProvider;

    @Autowired
    public void init(AuthenticationManagerBuilder builder) throws Exception {
        builder.authenticationProvider(authProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and()
                .addFilterBefore(authFilter(),
                        UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/oauth**", "/login**", "/status/**").permitAll()
                .anyRequest().authenticated()
                .and().csrf().disable()
                .formLogin().permitAll();
    }


    private UsernamePasswordAuthenticationFilter authFilter() {
        return new AuthFilter(authProvider);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    public class WebSecurityCorsFilter implements Filter {
        @Override
        public void init(FilterConfig filterConfig) throws ServletException {
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            HttpServletResponse res = (HttpServletResponse) response;
            res.setHeader("Access-Control-Allow-Origin", "*");
            res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT");
            res.setHeader("Access-Control-Max-Age", "3600");
            res.setHeader("Access-Control-Allow-Credentials", "true");
            res.setHeader("Access-Control-Allow-Headers", "Authorization," +
                    "Content-Type," +
                    "content-type," +
                    "Accept," +
                    "x-requested-with," +
                    "Cache-Control," +
                    "username," +
                    "password," +
                    "client_id," +
                    "client_secret," +
                    "grant_type," +
                    "scope"
            );
            chain.doFilter(request, res);
        }

        @Override
        public void destroy() {
        }
    }


}
