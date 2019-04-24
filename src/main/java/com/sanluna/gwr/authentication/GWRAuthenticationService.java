package com.sanluna.gwr.authentication;

import com.sanluna.commons.BeansAndConfigurations;
import com.sanluna.gwr.authentication.security.GWRAuthenticationProvider;
import com.sanluna.gwr.memberclient.MemberClientConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
@Import({BeansAndConfigurations.class, MemberClientConfiguration.class})
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
    public GWRAuthenticationProvider getAuthenticationProvider() {
        return new GWRAuthenticationProvider();
    }

}
