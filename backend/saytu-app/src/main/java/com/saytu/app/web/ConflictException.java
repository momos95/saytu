package com.saytu.app.web;

/** Mapped to HTTP 409 (duplicate name, stale version...). */
public class ConflictException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ConflictException(String message) {
        super(message);
    }
}
