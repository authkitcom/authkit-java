package com.authkit;

import java.io.IOException;
import java.io.InputStream;

public final class Util {

  public static final <T> T orDefault(T value, T defaultValue) {
    return value == null ? defaultValue : value;
  }

  public static final <T> T required(T value, String label) {
    if (value == null) {
      throw new IllegalArgumentException(String.format("%s is required", label));
    }
    return value;
  }

  public static void close(InputStream input) {
    if (input != null) {
      try {
        input.close();
      } catch (IOException e) {
        // IGNORE
      }
    }
  }
}
