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
        http.addFilterBefore(authFilter(),
                UsernamePasswordAuthenticationFilter.class)
                .cors().and()
                .authorizeRequests()
                .antMatchers("/oauth**", "/login**", "/status/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .csrf().disable()
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
}
