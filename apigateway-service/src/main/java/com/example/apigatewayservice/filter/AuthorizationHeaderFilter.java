package com.example.apigatewayservice.filter;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    Environment env;

    public AuthorizationHeaderFilter(Environment env){
        super(Config.class);        // custom하는 filter의 설정정보를 아래처럼 아쓰더라도 부모 클래스에 전달해서 알려줘야 한다.!!!
        this.env = env;
    }
    public static class Config{
    }

    // login -> token -> users(with token) -> header(include token)
    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            // exchange : 요청+응답 객체
            ServerHttpRequest request = exchange.getRequest();

            // 헤더 안 권한 안에 있는 토큰이 있을 때만 정상작동
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer", "");

            if(!isJwtValid(jwt)){
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        });
    }

    // jwt 유효값 확인
    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;

        String subject = null;

        try{
            // parseClaimsJwt 가 아니라 parseClaimsJws임.....
            subject = Jwts.parser().setSigningKey(env.getProperty("token.secret"))
                    .parseClaimsJws(jwt).getBody()
                    .getSubject();
        }catch (Exception ex){
            returnValue = false;
        }

        // User_id 랑 비교하지는 않고, 일단 유효한 id가 들어있는지만 확인하는 로직.
        if(subject == null || subject.isEmpty()){
            returnValue = false;
        }

        return returnValue;
    }

    // Mono(단일값), Flux(다중값) -> Spring WebFlux(spring 5.0부터 응답해주는 객체) => 데이터 처리방식이 "비동기 방식"
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(err);
        return response.setComplete();  // Mono 타입으로 전달 가능.
    }
}
