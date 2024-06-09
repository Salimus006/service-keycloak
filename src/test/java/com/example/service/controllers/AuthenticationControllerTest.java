package com.example.service.controllers;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.stream.Stream;

import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@SpringBootTest
@WebAppConfiguration
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AuthenticationControllerTest extends AbstractKeycloakTest {

    @Autowired
    private MockMvc mvc;

    private static ObjectMapper mapper;

    @BeforeAll
    static void test() {
        mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }


    private static String ADMIN_ACCESS_TOKEN;
    private static String ADMIN_REFRESH_TOKEN;
    private static String USER_ACCESS_TOKEN;
    private static String USER_REFRESH_TOKEN;

    @DynamicPropertySource
    static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM_NAME);
        registry.add("keycloak.base-url", () -> KEYCLOAK.getAuthServerUrl());
        registry.add("keycloak.client-realm", () -> REALM_NAME);
        registry.add("keycloak.client-id", () -> CLIENT_ID);
        registry.add("keycloak.client-secret", () -> CLIENT_SECRET);
    }

    @Order(1)
    @ParameterizedTest
    @MethodSource("provideAdminAndUserCredentials")
    void getAccessTokenSuccess(String userName, String password) throws Exception {

        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add("userName", userName);
        mapForm.add("password", password);

        // POST /auth/authenticate/password with pathParam username and password
        MvcResult result = mvc.perform(post("/auth/authenticate/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .params(mapForm))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.access_token", notNullValue()))
                .andExpect(jsonPath("$.refresh_token", notNullValue()))
                .andReturn();

        TokenDTO tokenResponse = mapper.readValue(result.getResponse().getContentAsString(), TokenDTO.class);
        if ("admin".equals(userName)) {
            ADMIN_ACCESS_TOKEN = tokenResponse.accessToken();
            ADMIN_REFRESH_TOKEN = tokenResponse.refreshToken();
        } else {
            USER_ACCESS_TOKEN = tokenResponse.accessToken();
            USER_REFRESH_TOKEN = tokenResponse.refreshToken();
        }
    }

    @Test
    void getAccessTokenFail() throws Exception {

        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add("userName", "wrongUser");
        mapForm.add("password", "wrongPassword");

        // POST /auth/authenticate/password with pathParam username and password
        mvc.perform(post("/auth/authenticate/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .params(mapForm))
                .andExpect(status().isUnauthorized());
    }

    @Order(2)
    @ParameterizedTest
    @ValueSource(strings = {"admin", "user"})
    void refreshAccessTokenSuccess(String userType) throws Exception {

        String refreshToken = "admin".equals(userType) ? ADMIN_REFRESH_TOKEN : USER_REFRESH_TOKEN;

        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add("refreshToken", refreshToken);

        // POST /auth/authenticate/refresh with pathParam refreshToken
        mvc.perform(post("/auth/authenticate/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .params(mapForm))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.access_token", notNullValue()));
    }

    @Test
    void refreshAccessTokenFail() throws Exception {

        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add("refreshToken", "wrongToken");

        // POST /auth/authenticate/refresh with pathParam refreshToken
        mvc.perform(post("/auth/authenticate/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .params(mapForm))
                .andExpect(status().isUnauthorized());
    }

    @Order(3)
    @ParameterizedTest
    @ValueSource(strings = {"admin", "user"})
    void authenticationInfo(String userType) throws Exception {

        String token;
        String expectedAuthority;
        if ("admin".equals(userType)) {
            token = ADMIN_ACCESS_TOKEN;
            expectedAuthority = "ADMIN";
        } else {
            token = USER_ACCESS_TOKEN;
            expectedAuthority = "USER";
        }
        // Call authentication endpoint (GET /auth/info)
        mvc.perform(get("/auth/info")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authorities").isArray())
                // check that in authorities array contains at least the expected authority (ADMIN for admin user and USER for user)
                .andExpect(jsonPath("$.authorities[*].authority", hasItems(expectedAuthority)));
    }

    @Order(4)
    @ParameterizedTest
    @ValueSource(strings = {"admin", "user"})
    void logoutSuccess(String userType) throws Exception {
        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();

        if ("admin".equals(userType)) {
            mapForm.add("accessToken", ADMIN_ACCESS_TOKEN);
            mapForm.add("refreshToken", ADMIN_REFRESH_TOKEN);
        } else {
            mapForm.add("accessToken", USER_ACCESS_TOKEN);
            mapForm.add("refreshToken", USER_REFRESH_TOKEN);
        }

        // POST /auth/authenticate/logout with pathParam accessToken and refreshToken
        mvc.perform(post("/auth/authenticate/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .params(mapForm))
                .andExpect(status().isNoContent());
    }

    @Test
    void logoutFail() throws Exception {
        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
            mapForm.add("accessToken", "invalidAccessToken");
            mapForm.add("refreshToken", "invalidRefreshToken");

        // POST /auth/authenticate/logout with pathParam accessToken and refreshToken
        mvc.perform(post("/auth/authenticate/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .params(mapForm))
                .andExpect(status().isUnauthorized());
    }

    private static Stream<Arguments> provideAdminAndUserCredentials() {
        return Stream.of(
                Arguments.of("user", "1234"),
                Arguments.of("admin", "1234")
        );
    }
}
