package com.authkit;

public class AuthkitException extends RuntimeException {

  public AuthkitException() {
    super();
  }

  public AuthkitException(String message) {
    super(message);
  }

  public AuthkitException(String message, Throwable cause) {
    super(message, cause);
  }

  public AuthkitException(Throwable cause) {
    super(cause);
  }
}
