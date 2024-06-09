package com.example.service.controllers;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
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
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.DockerClientFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractKeycloakTest {
    protected static RestTemplate restTemplate = new RestTemplate();

    protected static final String REALM_IMPORT_FILE = "/keycloak/imports/realm-export.json";
    protected static final String REALM_NAME = "spring_boot_service";
    protected static final String CLIENT_NAME = "spring_boot_service";
    protected static final String CLIENT_ID = "spring_boot_service_client";
    protected static final String CLIENT_SECRET = "HmoDZeRFplZzcshdVKCF9IqczDj1cFBw";

    private static final String CLIENT_AUTHENTICATOR_TYPE = "client-secret";
    private static String ADMIN_CLI_ACCESS_TOKEN;
    private static String MY_ADMIN_LOCATION;
    private static String MY_USER_LOCATION;
    private static String ADMIN_ROLE_UUID;
    private static String USER_ROLE_UUID;
    protected static KeycloakContainer KEYCLOAK;

    @BeforeAll
    public static void beforeAll() throws URISyntaxException, VerificationException {
        KEYCLOAK = new KeycloakContainer()
                .withAdminUsername("admin")
                .withAdminPassword("admin")
                .withRealmImportFile(REALM_IMPORT_FILE);

        KEYCLOAK.start();
        // check if docker is running
        assertTrue(AbstractKeycloakTest::isDockerAvailable);

        // check test context (admin is connected, realm, client and roles are created with the imported file)
        checkBeforeAll();

        // create two users one with 'ADMIN' role and another with 'USER' role
        createUsers();

        assignRoleToUser("admin");
        assignRoleToUser("user");
    }

    @AfterAll
    public static void afterAll() {
        KEYCLOAK.stop();
    }

    private static boolean isDockerAvailable() {
        try {
            DockerClientFactory.instance().client();
            return true;
        } catch (Throwable ex) {
            return false;
        }
    }

    private static void checkBeforeAll() throws VerificationException {
        // Check admin-cli token
        AccessTokenResponse accessTokenResponse = retrieveAdminToken();
        // get the admin access token to verify
        String adminAccessToken = accessTokenResponse.getToken();
        Assertions.assertNotNull(adminAccessToken);
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(adminAccessToken, AccessToken.class);
        verifier.parse();

        // check token claims
        AccessToken accessToken = verifier.getToken();
        assertEquals("admin", accessToken.getPreferredUsername());
        assertEquals("admin-cli", accessToken.issuedFor);

        ADMIN_CLI_ACCESS_TOKEN = adminAccessToken;

        // check realm and client creation
        List<ClientRepresentation> clients = KEYCLOAK.getKeycloakAdminClient().realm(REALM_NAME)
                .clients().findByClientId(CLIENT_ID);

        assertEquals(1, clients.size());
        ClientRepresentation client = clients.get(0);
        // check clientId = spring_boot_service_client, name=spring_boot_service, clientAuthenticatorType=client-secret
        // secret="mySecret", protocol=openid-connect
        assertEquals(CLIENT_ID, client.getClientId());
        assertEquals(CLIENT_NAME, client.getName());
        assertEquals(CLIENT_AUTHENTICATOR_TYPE, client.getClientAuthenticatorType());
        assertEquals(CLIENT_SECRET, client.getSecret());
        assertEquals("openid-connect", client.getProtocol());

        // check realm roles
        List<RoleRepresentation> realmRoles = KEYCLOAK.getKeycloakAdminClient().realm(REALM_NAME).roles().list()
                .stream().filter(r -> r.getName().equals("ADMIN") || r.getName().equals("USER")).toList();

        assertEquals(2, realmRoles.size());

        realmRoles.forEach(roleRepresentation -> {
            String roleName = roleRepresentation.getName();
            String roleUUid = roleRepresentation.getId();
            if ("ADMIN".equals(roleName)) {
                ADMIN_ROLE_UUID = roleUUid;
            } else if ("USER".equals(roleName)) {
                USER_ROLE_UUID = roleUUid;
            }
        });
    }

    private static void createUsers() {
        final UsersResource usersResource = KEYCLOAK.getKeycloakAdminClient().realm(REALM_NAME).users();

        UserRepresentation adminRepresentation = getUserRepresentation("admin");
        UserRepresentation userRepresentation = getUserRepresentation("user");


        try (Response responseForAdminCreation = usersResource.create(adminRepresentation);
             Response responseForUserCreation = usersResource.create(userRepresentation)) {
            // check response
            MY_ADMIN_LOCATION = (String) responseForAdminCreation.getHeaders().get("Location").get(0);
            MY_USER_LOCATION = (String) responseForUserCreation.getHeaders().get("Location").get(0);
            // check users
            KEYCLOAK.getKeycloakAdminClient().realm(REALM_NAME).users();
        }
    }

    private static UserRepresentation getUserRepresentation(String userType) {
        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setUsername(userType);
        userRepresentation.setFirstName(userType);
        userRepresentation.setLastName(userType.toUpperCase());
        userRepresentation.setEmail(userType + "@gmail.com");
        userRepresentation.setEmailVerified(false);
        userRepresentation.setEnabled(true);

        CredentialRepresentation userCredentials = new CredentialRepresentation();
        userCredentials.setTemporary(false);
        userCredentials.setType("password");
        userCredentials.setValue("1234");
        userRepresentation.setCredentials(List.of(userCredentials));

        return userRepresentation;
    }

    private static void assignRoleToUser(String userType) throws URISyntaxException {
        Map<String, String> mapBody = new HashMap<>();
        URI assignRoleUri = null;

        switch (userType) {
            case "admin" -> {
                mapBody.putIfAbsent("id", ADMIN_ROLE_UUID);
                mapBody.putIfAbsent("name", "ADMIN");
                assignRoleUri = new URIBuilder(MY_ADMIN_LOCATION + "/role-mappings/realm").build();
            }
            case "user" -> {
                mapBody.putIfAbsent("id", USER_ROLE_UUID);
                mapBody.putIfAbsent("name", "USER");
                assignRoleUri = new URIBuilder(MY_USER_LOCATION + "/role-mappings/realm").build();
            }
        }

        List<Map<String, String>> arrayBody = new ArrayList<>();
        arrayBody.add(mapBody);

        // make a call to keycloak to assign roles
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/json");
        headers.setBearerAuth(ADMIN_CLI_ACCESS_TOKEN);

        HttpEntity<List<Map<String, String>>> request = new HttpEntity<>(arrayBody, headers);

        assert assignRoleUri != null;
        ResponseEntity<Object> response = restTemplate.exchange(assignRoleUri,
                HttpMethod.POST,
                request, Object.class);

        // Check response status
        assertEquals(response.getStatusCode(), HttpStatus.NO_CONTENT);
    }

    private static AccessTokenResponse retrieveAdminToken() {
        return KEYCLOAK.getKeycloakAdminClient().tokenManager().getAccessToken();
    }

    protected KeyCloakToken getTokenFromKeycloak(HttpHeaders headers,
                                                                     MultiValueMap<String, String> mapForm) throws URISyntaxException {

        URI authorizationUri = new URIBuilder(String.format("%s/realms/%s/protocol/openid-connect/token",
                KEYCLOAK.getAuthServerUrl(), REALM_NAME)).build();

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);

        ResponseEntity<KeyCloakToken> response = restTemplate.exchange(authorizationUri,
                HttpMethod.POST,
                request, KeyCloakToken.class);
        return response.getBody();
    }

    protected record KeyCloakToken(String accessToken, int expiresIn, String tokenType) {

        @JsonCreator
        public KeyCloakToken(@JsonProperty("access_token") final String accessToken,
                                @JsonProperty("expires_in") final int expiresIn,
                                @JsonProperty("token_type") final String tokenType) {
            this.accessToken = accessToken;
            this.expiresIn = expiresIn;
            this.tokenType = tokenType;
        }
    }

}
