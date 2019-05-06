package com.sanluna.gwr.authentication;

import com.sanluna.BeansAndConfigurations;
import com.sanluna.GWRClientConfiguration;
import com.sanluna.gwr.authentication.security.GWRAuthenticationProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

@SpringBootApplication
@Import({BeansAndConfigurations.class, GWRClientConfiguration.class})
public class GWRAuthenticationService {

    public static void main(String[] args) {
        SpringApplication.run(GWRAuthenticationService.class, args);
    }

    @Bean
    @Primary
    public GWRAuthenticationProvider getAuthenticationProvider() {
        return new GWRAuthenticationProvider();
    }

}
