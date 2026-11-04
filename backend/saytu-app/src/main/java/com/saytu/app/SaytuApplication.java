package com.saytu.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SaytuApplication {

    public static void main(String[] args) {
        SpringApplication.run(SaytuApplication.class, args);
    }
}
