package ru.morningcake.agw.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class UnauthorisedException extends ResponseStatusException {

  public UnauthorisedException(HttpStatus status) {
    super(status);
  }

  public UnauthorisedException(HttpStatus status, String reason) {
    super(status, reason);
  }

}