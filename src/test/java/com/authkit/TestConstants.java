package com.authkit;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public final class TestConstants {

  static {
    System.setProperty("reactor.netty.channel.FluxReceive", "DEBUG");
    System.setProperty("io.netty.leakDetection.level", "paranoid");
  }

  public static final String ISSUER = "http://localhost:9996";
  public static final String AUDIENCE = "test-audience";

  public static final Gson GSON =
      new GsonBuilder()
          .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
          .create();

  private TestConstants() {}
  ;
}
