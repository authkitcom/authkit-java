package com.authkit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;

public class UtilTest {

    @ParameterizedTest
    @MethodSource("orDefaultValues")
    public void orDefault(Object provided, Object defaultValue, Object expected) {

        assertThat(Util.orDefault(provided, defaultValue)).isEqualTo(expected);
    }

    static Stream<Arguments> orDefaultValues() {
        return Stream.of(
                arguments(null, null, null),
                arguments("provided", "default", "provided"),
                arguments("provided", null, "provided"),
                arguments(null, "default", "default")
        );
    }

    @Test
    public void required_notNull() {

        String value = "value";
        assertThat(Util.required(value, "Value")).isSameAs(value);

    }

    @Test
    public void required_null() {

        assertThatThrownBy(() -> Util.required((String ) null, "Value"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Value is required");
    }

}