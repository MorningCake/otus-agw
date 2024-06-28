package ru.morningcake.agw;

import org.springframework.boot.SpringApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import ru.morningcake.annotation.OtusSpringBootApplication;

/**
 */
@OtusSpringBootApplication
@EnableFeignClients(basePackages = {"ru.morningcake.agw.feign"})
public class AuthGatewayApplication {

  public static void main(String[] args) {
    SpringApplication.run(AuthGatewayApplication.class, args);
  }

}
