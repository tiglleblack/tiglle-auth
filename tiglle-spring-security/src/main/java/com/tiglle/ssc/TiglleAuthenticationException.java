package com.tiglle.ssc;

import org.springframework.security.core.AuthenticationException;

public class TiglleAuthenticationException extends AuthenticationException {
    public TiglleAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public TiglleAuthenticationException(String msg) {
        super(msg);
    }

    public static void main(String[] args) {
        
    }
}
