package com.example.service.controllers;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.DockerClientFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@SpringBootTest
@WebAppConfiguration
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CountryControllerTest extends AbstractKeycloakTest {

    @Autowired
    private MockMvc mvc;
    private static String USER_ACCESS_TOKEN;
    private static String ADMIN_ACCESS_TOKEN;
    private static final String USER_USER_NAME = "user";
    private static final String USER_USER_PASSWORD = "1234";
    private static final String ADMIN_USER_NAME = "admin";
    private static final String ADMIN_USER_PASSWORD = "1234";

    @DynamicPropertySource
    static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM_NAME);
        registry.add("keycloak.base-url", () -> KEYCLOAK.getAuthServerUrl());
        registry.add("keycloak.client-realm", () -> REALM_NAME);
        registry.add("keycloak.client-id", () -> CLIENT_ID);
        registry.add("keycloak.client-secret", () -> CLIENT_SECRET);
    }

    @Test
    @Order(1)
    void getAdminTokenFromKeycloakTest() throws URISyntaxException, VerificationException {
        // authenticate user with role 'USER'
        //headers
        HttpHeaders keyCloakCallHeaders = new HttpHeaders();
        keyCloakCallHeaders.add("Content-Type", "application/x-www-form-urlencoded");

        // body form-urlencoded
        MultiValueMap<String, String> mapForm= new LinkedMultiValueMap<>();
        mapForm.add("grant_type", "password");
        mapForm.add("client_id", CLIENT_ID);
        mapForm.add("client_secret", CLIENT_SECRET);
        mapForm.add("username", ADMIN_USER_NAME);
        mapForm.add("password", ADMIN_USER_PASSWORD);

        CountryControllerTest.KeyCloakToken keyCloakToken = getTokenFromKeycloak(keyCloakCallHeaders, mapForm);

        String token = keyCloakToken.accessToken();

        Assertions.assertNotNull(token);
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class);
        verifier.parse();

        // check token claims
        AccessToken accessToken = verifier.getToken();
        assertEquals("admin", accessToken.getPreferredUsername());
        // check that realm access roles contain 'ADMIN role'
        Set<String> roles = accessToken.getRealmAccess().getRoles();
        assertTrue(roles.contains("ADMIN"));

        ADMIN_ACCESS_TOKEN = token;
    }
    @Test
    @Order(2)
    void getUserTokenFromKeycloakTest() throws URISyntaxException, VerificationException {
        // authenticate user with role 'USER'
        //headers
        HttpHeaders keyCloakCallHeaders = new HttpHeaders();
        keyCloakCallHeaders.add("Content-Type", "application/x-www-form-urlencoded");

        // body form-urlencoded
        MultiValueMap<String, String> mapForm= new LinkedMultiValueMap<>();
        mapForm.add("grant_type", "password");
        mapForm.add("client_id", CLIENT_ID);
        mapForm.add("client_secret", CLIENT_SECRET);
        mapForm.add("username", USER_USER_NAME);
        mapForm.add("password", USER_USER_PASSWORD);

        CountryControllerTest.KeyCloakToken keyCloakToken = getTokenFromKeycloak(keyCloakCallHeaders, mapForm);

        String token = keyCloakToken.accessToken();

        Assertions.assertNotNull(token);
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class);
        verifier.parse();

        // check token claims
        AccessToken accessToken = verifier.getToken();
        assertEquals("user", accessToken.getPreferredUsername());

        // check that realm access roles contain 'ADMIN role'
        Set<String> roles = accessToken.getRealmAccess().getRoles();
        assertTrue(roles.contains("USER"));

        USER_ACCESS_TOKEN = token;
    }

    @Test
    @Order(3)
    void getClientAccessTokenTest() throws VerificationException, URISyntaxException {
        // headers
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        // body form-urlencoded
        MultiValueMap<String, String> mapForm= new LinkedMultiValueMap<>();
        mapForm.add("grant_type", "client_credentials");
        mapForm.add("client_id", CLIENT_ID);
        mapForm.add("client_secret", CLIENT_SECRET);

        CountryControllerTest.KeyCloakToken keycloakResponse = this.getTokenFromKeycloak(headers, mapForm);

        // get the access token to verify
        String retrievedAccessToken = keycloakResponse.accessToken();
        Assertions.assertNotNull(retrievedAccessToken);

        // parse the received access-token
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(retrievedAccessToken, AccessToken.class);
        verifier.parse();

        // check for the custom claim
        AccessToken accessToken = verifier.getToken();
        assertEquals("service-account-spring_boot_service_client", accessToken.getPreferredUsername());
    }

    @ParameterizedTest
    @ValueSource(strings = {"USER", "ADMIN"})
    void getAllCountriesTest(String userType) throws Exception {
        String token = "ADMIN".equals(userType) ? ADMIN_ACCESS_TOKEN : USER_ACCESS_TOKEN;
        // call endpoint protected with 'USER' authority
        mvc.perform(get("/api/countries")
                        .contentType(MediaType.APPLICATION_JSON).header("authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("*").isArray())
                .andExpect(jsonPath("$.*", hasSize(5)))

                .andExpect(jsonPath("$[0].id", is(1)))
                .andExpect(jsonPath("$[0].name", is("USA")))

                .andExpect(jsonPath("$[1].id", is(2)))
                .andExpect(jsonPath("$[1].name", is("FRANCE")))

                .andExpect(jsonPath("$[2].id", is(3)))
                .andExpect(jsonPath("$[2].name", is("BRAZIL")))

                .andExpect(jsonPath("$[3].id", is(4)))
                .andExpect(jsonPath("$[3].name", is("ITALY")))

                .andExpect(jsonPath("$[4].id", is(5)))
                .andExpect(jsonPath("$[4].name", is("CANADA")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"USER", "ADMIN"})
    void findCountryByIdTest(String userType) throws Exception {
        String token = "ADMIN".equals(userType) ? ADMIN_ACCESS_TOKEN : USER_ACCESS_TOKEN;
        mvc.perform(get("/api/countries/{id}", 1)
                .contentType(MediaType.APPLICATION_JSON).header("authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id", is(1))).andExpect(jsonPath("$.name", is("USA")));
    }

    @Test
    void saveCountryTest() throws Exception {
        String spain = "{\"id\": 6, \"name\": \"SPAIN\"}";

        mvc.perform(post("/api/countries")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("authorization", "Bearer " + ADMIN_ACCESS_TOKEN)
                        .content(spain))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id", is(6)))
                .andExpect(jsonPath("$.name", is("SPAIN")));
    }
}
