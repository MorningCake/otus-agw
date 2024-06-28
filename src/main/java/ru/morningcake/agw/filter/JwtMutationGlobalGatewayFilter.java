package ru.morningcake.agw.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.morningcake.agw.exception.UnauthorisedException;
import ru.morningcake.jwt.JwtToken;
import ru.morningcake.utils.Const;
import ru.morningcake.utils.TimeUtils;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Фильтр регистрации, аутентификации и проверки аутентификации
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtMutationGlobalGatewayFilter implements GlobalFilter, Ordered {

  private final Map<String, Pair<UUID, Long>> loginAndAccessIdExpPair = new ConcurrentHashMap<>();
  private final ObjectMapper objectMapper;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    // Расширенное логирование (нельзя логировать Auth целиком) - включается в конфиге
    ServerHttpRequest request = exchange.getRequest();
    // проверка роута. Если он на url логин или регистрации - токен не нужен. для остальных роутов - нужен, проверка
    if (request.getPath().toString().equals("/api/registration") && request.getMethod() == HttpMethod.POST) {
      return chain.filter(exchange);
    } else if (request.getPath().toString().equals("/api/login") && request.getMethod() == HttpMethod.POST) {
      // при логине вычитать хэдер с jwt и положит данные в мапу
      ServerHttpResponse response = exchange.getResponse();
      DataBufferFactory dataBufferFactory = response.bufferFactory();
      ServerHttpResponseDecorator decoratedResponse = getDecoratedResponse(response, request, dataBufferFactory);

      return chain.filter(
          exchange.mutate().request(request).response(decoratedResponse).build());
    } else {
      // в остальных случаях ПРОВЕРИТЬ ТОКЕН по мапе
      // Токен состоит из 2 частей: 1 - access uuid генерируемый на БД при логине, 2 - данные (роли groups, accessId, exp)
      // при логине генерится случайный uuid, который раз в сутки протухает (шедулером раз в 15 мин проверка, чистка в ms-user и мапы).
      var chunks = getAccessAndTokenPayload(request);
      String jwtChunk = chunks[1];
      String jwtData = new String(Base64.getUrlDecoder().decode(jwtChunk), StandardCharsets.UTF_8);
      JwtToken token = JwtToken.getJwtTokenFromJson(jwtData, objectMapper);
      if (loginAndAccessIdExpPair.containsKey(token.getUsername())) {
        Pair<UUID, Long> accessIdAndExp = loginAndAccessIdExpPair.get(token.getUsername());
        if (!accessIdAndExp.getKey().equals(token.getAccessId()) ) {
          return forbidden(exchange, "AccessId is not equal!");
        } else if (
            TimeUtils.getTimeFromExp(accessIdAndExp.getValue(), TimeUtils.getDefaultZoneOffset())
                .isBefore(LocalDateTime.now())
        ) {
          loginAndAccessIdExpPair.remove(token.getUsername());
          return forbidden(exchange, "Token Expired");
        }
      } else {
        return forbidden(exchange, "Need Authorization!");
      }
      log.debug("Received token payload = {}", chunks[1]);

      return chain.filter(
          exchange
              .mutate()
              .request(
                  request
                      .mutate()
                      .headers(headers -> headers.add(Const.SEC_CONTEXT_HEADER, chunks[1]))
                      .build()
              ).build()
      );
    }
  }

  @Override
  public int getOrder() {
    return -1;
  }


  private Mono<Void> forbidden(ServerWebExchange exchange, String message) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(HttpStatus.FORBIDDEN);
    byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
    DataBuffer buffer = response.bufferFactory().wrap(bytes);
    return response.writeWith(Mono.just(buffer));
  }

  // фейк, чтобы прочитать хэдеры после
  private ServerHttpResponseDecorator getDecoratedResponse(ServerHttpResponse response, ServerHttpRequest request, DataBufferFactory dataBufferFactory) {
    return new ServerHttpResponseDecorator(response) {

      @Override
      @SneakyThrows
      public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
        List<String> tokens = response.getHeaders().get(Const.JWT_RESPONSE_HEADER);
        if (!CollectionUtils.isEmpty(tokens)) {
          String jwt = tokens.get(0);
          String jwtChunk = jwt.split("\\.")[1];
          String jwtData = new String(Base64.getUrlDecoder().decode(jwtChunk), StandardCharsets.UTF_8);
          JwtToken token = objectMapper.readValue(jwtData, JwtToken.class);
          loginAndAccessIdExpPair.put(token.getUsername(), new ImmutablePair<>(token.getAccessId(), token.getExp()));
        }
        return super.writeWith(body);
      }
    };
  }

  private String[] getAccessAndTokenPayload(ServerHttpRequest request) {
    String header = Optional.of(request.getHeaders())
        .map(i -> i.get(HttpHeaders.AUTHORIZATION))
        .flatMap(i -> i.stream().findFirst())
        .orElseThrow(() -> new UnauthorisedException(HttpStatus.UNAUTHORIZED, "Need Authorization!"));
    return header.split(" ")[1].split("\\.");
  }

}
