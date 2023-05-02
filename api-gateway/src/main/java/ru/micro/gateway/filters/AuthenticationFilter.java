package ru.micro.gateway.filters;

import com.ctc.wstx.shaded.msv_core.util.Uri;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import ru.micro.gateway.exception.JwtAuthenticationException;
import ru.micro.gateway.security.RouterValidator;

import java.net.URI;

@RefreshScope
@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private RouterValidator routerValidator;
    private RestTemplate restTemplate;
    @Value("${key.security_adress}")
    private String securityAdress;

    public AuthenticationFilter(RouterValidator routerValidator, RestTemplate restTemplate) {
        super(Config.class);
        this.routerValidator = routerValidator;
        this.restTemplate = restTemplate;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (routerValidator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new JwtAuthenticationException("missing authorization header", HttpStatus.FORBIDDEN);
                }
                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if(!validate(authHeader)){
                    throw new JwtAuthenticationException("Authorization failure", HttpStatus.FORBIDDEN);
                }
            }
            return chain.filter(exchange);
        });
    }

    private Boolean validate(String authHeader){
        try {
           return restTemplate.getForObject(securityAdress + "validate?token=" + authHeader, Boolean.class);
        } catch (Exception e) {
          throw new JwtAuthenticationException("Authorization failure. Server Error", HttpStatus.FORBIDDEN);
        }
    }

    public static class Config {

    }

}
