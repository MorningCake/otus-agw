package ru.morningcake.agw.config.filter;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.naming.AuthenticationException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Фильтр, достающий из контекста только необходимую для определения пользователя информацию
 */
@Component
@Slf4j
public class JwtMutationGlobalGatewayFilter implements GlobalFilter, Ordered {

  @SneakyThrows
  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    // Расширенное логирование (нельзя логировать Auth целиком) - включается в конфиге
    ServerHttpRequest request = exchange.getRequest();
    ServerHttpResponse response = exchange.getResponse();

    // проверка роута. Если он на url логин или регистрации - токен не нужен. для остальных роутов - нужен, проверка
    if (request.getPath().toString().equals("/api/user/login") && request.getMethod() == HttpMethod.POST) {
      response.setStatusCode(HttpStatus.OK);
      // todo вместо ОК вставить токен при успешном логине и 401 при неуспешном - завести БИН
      byte[] bytes = "OK".getBytes(StandardCharsets.UTF_8);

      DataBuffer buffer = response.bufferFactory().wrap(bytes);
      return response.writeWith(Mono.just(buffer));
    } else if (request.getPath().toString().equals("/api/user/registration") && request.getMethod() == HttpMethod.POST) {
      // TODO регистрация - добавить БД и бин регистрации
    }
    // в остальных случаях ПРОВЕРИТЬ ТОКЕН по БД. Токен состоит из 3 частей: 1 - access uuid генерируемый на БД при логине, 2 - данные (роли, ФИО, exp) 3- бла бла вместо серта
    // при логине генерится случайный uuid, который раз в сутки протухает (шедулером). Время протухания пишем в exp
    // при проверке логина сравниваем uuid с БД, не совпал - 403, совпал - идем далее в микросервис, прокидывая хэдер


    // переложить центральную часть токена в хэдер X-Security-Context
    var tokenPayload = getTokenPayloadFromRequest(request);
    log.debug("Received token payload = {}", tokenPayload);

    return chain.filter(
        exchange
            .mutate()
            .request(
                request
                    .mutate()
                    .headers(headers -> headers.add("X-Security-Context", tokenPayload))
                    .build()
            )
            .build()
    );
  }

  private String getTokenPayloadFromRequest(ServerHttpRequest request) throws AuthenticationException {
    String header = Optional.of(request.getHeaders())
        .map(i -> i.get(HttpHeaders.AUTHORIZATION))
        .flatMap(i -> i.stream().findFirst())
        .orElseThrow(() -> new AuthenticationException("401 - Not Authorized! (empty token)"));
    String[] chunks = header.split(" ")[1].split("\\.");
    return chunks[1];
  }

  @Override
  public int getOrder() {
    return -1;
  }
}
