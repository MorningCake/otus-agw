package ru.morningcake.agw.exception;

import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import reactor.core.publisher.Mono;

@ControllerAdvice
@Order(4)
public class AgwExceptionHandler extends ResponseEntityExceptionHandler {

  @ExceptionHandler(UnauthorisedException.class)
  public Mono<ServerResponse> handleIllegalState(ServerWebExchange exchange, UnauthorisedException exc) {
    exchange.getAttributes().putIfAbsent(ErrorAttributes.ERROR_ATTRIBUTE, exc);
//    return ServerResponse.from(ErrorResponse.builder(exc, HttpStatus.FORBIDDEN,exc.getMessage()).build());
    return ServerResponse.status(HttpStatus.FORBIDDEN).bodyValue(exc);
  }

}
