package com.example.service.controllers;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URISyntaxException;
import java.util.Set;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@AutoConfigureMockMvc
@SpringBootTest
@WebAppConfiguration
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AuthenticationControllerTest extends AbstractKeycloakTest {

    @Autowired
    private MockMvc mvc;

    @DynamicPropertySource
    static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM_NAME);
        registry.add("keycloak.base-url", () -> KEYCLOAK.getAuthServerUrl());
        registry.add("keycloak.client-realm", () -> REALM_NAME);
        registry.add("keycloak.client-id", () -> CLIENT_ID);
        registry.add("keycloak.client-secret", () -> CLIENT_SECRET);
    }

    @ParameterizedTest
    @MethodSource("provideAdminAndUserCredentials")
    void getTokenFromMyApi(String userName, String password) throws Exception {
        // authenticate user with role 'USER'
        //headers
        HttpHeaders keyCloakCallHeaders = new HttpHeaders();
        keyCloakCallHeaders.add("Content-Type", "application/json");

        // body form-urlencoded
        MultiValueMap<String, String> mapForm= new LinkedMultiValueMap<>();
        mapForm.add("userName", userName);
        mapForm.add("password", password);

        // POST /auth/authenticate/password with pathParam username and password
        MvcResult result = mvc.perform(post("/auth/authenticate/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .params(mapForm))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.access_token", notNullValue())).andReturn();
    }


    private static Stream<Arguments> provideAdminAndUserCredentials() {
        return Stream.of(
                Arguments.of("user", "1234"),
                Arguments.of("admin", "1234")
        );
    }
}
