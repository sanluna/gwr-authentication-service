package com.sanluna.gwr.authentication;

import com.sanluna.commons.BeansAndConfigurations;
import com.sanluna.gwr.authentication.security.GWRAuthenticationProvider;
import com.sanluna.gwr.authentication.service.GWRUserDetailsService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import sanluna.gwr.security.SecurityConfiguration;

@SpringBootApplication
@Import({BeansAndConfigurations.class, SecurityConfiguration.class})
public class GWRAuthenticationService {

    public static void main(String[] args) {
        SpringApplication.run(GWRAuthenticationService.class, args);
    }

    @Bean
    @Primary
    public BCryptPasswordEncoder userPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Primary
    public GWRUserDetailsService userDetailsService() {
        return new GWRUserDetailsService();
    }

    @Bean
    @Primary
    public GWRAuthenticationProvider getAuthenticationProvider() {
        return new GWRAuthenticationProvider();
    }

}
