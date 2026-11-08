package com.saytu.app.web;

/** An optional integration (Keycloak administration, local AI) is not configured or not reachable: HTTP 503. */
public class ServiceUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ServiceUnavailableException(String message) {
        super(message);
    }
}
