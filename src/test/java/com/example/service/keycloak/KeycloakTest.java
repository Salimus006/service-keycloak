package com.example.service.keycloak;

import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;

public class KeycloakTest extends AbstractKeycloakTestContainers{

    @Test
    void getJwtTestSuccess() throws URISyntaxException {
        String bearer = requestToken();

        String test = "test";
    }
}
