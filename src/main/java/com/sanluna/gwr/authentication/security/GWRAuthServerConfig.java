package com.sanluna.gwr.authentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import sanluna.gwr.security.principal.GWRTokenConverter;

@Configuration
@EnableAuthorizationServer
public class GWRAuthServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Value("${GWR.security.prv}")
    private String prvKey;
    @Value("${GWR.security.pub}")
    private String pubKey;

    /**
     * We configure the client details in-memory. Alternatively, we could fetch this information from a database.
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("client")
                .secret(passwordEncoder.encode("secret"))
                .scopes("read")
                .authorizedGrantTypes("authorization_code", "client_credentials")
                .refreshTokenValiditySeconds(3600)
                .accessTokenValiditySeconds(600)
                .autoApprove(true);

    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .tokenEnhancer(accessTokenConverter());
    }

    @Bean
    @Primary
    public JwtAccessTokenConverter accessTokenConverter() {
        GWRTokenConverter converter = new GWRTokenConverter();
        converter.setSigningKey(prvKey);
        converter.setVerifierKey(pubKey);
        return converter;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.checkTokenAccess("isAuthenticated()").allowFormAuthenticationForClients();

    }
}
