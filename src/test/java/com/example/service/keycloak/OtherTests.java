package com.example.service.keycloak;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import org.apache.http.client.utils.URIBuilder;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.*;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.DockerClientFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OtherTests {

    private static final String REALM_IMPORT_FILE = "/keycloak/imports/realm-export.json";
    private static final String REALM_NAME = "spring_boot_service";
    private static final String CLIENT_NAME = "spring_boot_service";
    private static final String CLIENT_ID = "spring_boot_service_client";
    private static final String CLIENT_SECRET = "HmoDZeRFplZzcshdVKCF9IqczDj1cFBw";
    private static final String CLIENT_AUTHENTICATOR_TYPE = "client-secret";
    private static String ADMIN_CLI_ACCESS_TOKEN;
    private static String MY_ADMIN_LOCATION;
    private static String MY_USER_LOCATION;

    private static String ADMIN_ROLE_UUID;
    private static String USER_ROLE_UUID;

    private static final JacksonJsonParser jsonParser = new JacksonJsonParser();
    private static final RestTemplate restTemplate = new RestTemplate();
    public static KeycloakContainer KEYCLOAK;

    private static URI authorizationURI;

    @BeforeAll
    public static void beforeAll() throws URISyntaxException, VerificationException {
        // check if docker is running
        assertTrue(OtherTests::isDockerAvailable);
        // start keycloak container with admin user + realm file import
        KEYCLOAK = new KeycloakContainer()
                .withAdminUsername("admin")
                .withAdminPassword("admin").withRealmImportFile(REALM_IMPORT_FILE);

        KEYCLOAK.start();

        authorizationURI = new URIBuilder(KEYCLOAK.getAuthServerUrl() + "/realms/master/protocol/openid-connect/token").build();

        // check test context (admin is connected, realm, client and roles are created with the imported file)
        checkBeforeAll();

        // create two users one with 'ADMIN' role and another with 'USER' role
        createUsers();

        assignRoleToUser("admin");
        assignRoleToUser("user");
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

        List<Map<String,String>> arrayBody = new ArrayList<>();
        arrayBody.add(mapBody);

        // make a call to keycloak to assign roles
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/json");
        headers.setBearerAuth(ADMIN_CLI_ACCESS_TOKEN);

        HttpEntity<List<Map<String, String>>> request = new HttpEntity<>(arrayBody, headers);

        assert assignRoleUri != null;
        try {
            ResponseEntity<Object> response = restTemplate.exchange(assignRoleUri,
                    HttpMethod.POST,
                    request, Object.class);
        } catch (Exception e) {
            String error = "";
        }

    }

    @AfterAll
    public static void afterAll() {
        KEYCLOAK.stop();
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

        assertEquals(1,clients.size());
        ClientRepresentation client = clients.get(0);
        // check clientId = spring_boot_service_client, name=spring_boot_service, clientAuthenticatorType=client-secret
        // secret="mySecret", protocol=openid-connect
        assertEquals(CLIENT_ID,client.getClientId());
        assertEquals(CLIENT_NAME,client.getName());
        assertEquals(CLIENT_AUTHENTICATOR_TYPE,client.getClientAuthenticatorType());
        assertEquals(CLIENT_SECRET,client.getSecret());
        assertEquals("openid-connect",client.getProtocol());

        // check realm roles
        List<RoleRepresentation> realmRoles = KEYCLOAK.getKeycloakAdminClient().realm(REALM_NAME).roles().list()
                .stream().filter(r -> r.getName().equals("ADMIN") || r.getName().equals("USER")).toList();

        realmRoles.forEach(roleRepresentation -> {
            String roleName = roleRepresentation.getName();
            String roleUUid = roleRepresentation.getId();
            if("ADMIN".equals(roleName)) {
                ADMIN_ROLE_UUID = roleUUid;
            } else if ("USER".equals(roleName)) {
                USER_ROLE_UUID = roleUUid;
            }
        });

        assertEquals(2,realmRoles.size());
    }

    private static void createUsers() {
        final UsersResource usersResource = KEYCLOAK.getKeycloakAdminClient().realm(REALM_NAME).users();

        UserRepresentation adminRepresentation = getUserRepresentation("admin");
        UserRepresentation userRepresentation = getUserRepresentation("user");


        try(Response responseForAdminCreation = usersResource.create(adminRepresentation);
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
        userRepresentation.setEmail(userType+"@gmail.com");
        userRepresentation.setEmailVerified(false);
        userRepresentation.setEnabled(true);

        CredentialRepresentation userCredentials = new CredentialRepresentation();
        userCredentials.setTemporary(false);
        userCredentials.setType("password");
        userCredentials.setValue("1234");
        userRepresentation.setCredentials(List.of(userCredentials));

        //userRepresentation.setRealmRoles(List.of(userType.toUpperCase()));

        return userRepresentation;
    }

    private static boolean isDockerAvailable() {
        try {
            DockerClientFactory.instance().client();
            return true;
        } catch (Throwable ex) {
            return false;
        }
    }

    @Test
    void start() {
        String start = "start";
    }

    private static AccessTokenResponse retrieveAdminToken() {
        return KEYCLOAK.getKeycloakAdminClient().tokenManager().getAccessToken();
    }

    private String getBearerToken() {

        ClientsResource c = KEYCLOAK.getKeycloakAdminClient().realm("spring_boot_service").clients();
        Keycloak adminClient = KEYCLOAK.getKeycloakAdminClient();
        AccessTokenResponse at = adminClient.tokenManager().getAccessToken();
        ServerInfoResource serverInfo = adminClient.serverInfo();
        RolesResource roles = adminClient.realm("spring_boot_service").roles();

        UsersResource users = KEYCLOAK.getKeycloakAdminClient().realm("spring_boot_service").users();

        List<ClientRepresentation> clients = c.findAll();

        /*
        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setCreatedDate(new Date().getTime());
        credentialRepresentation.setId(UUID.randomUUID().toString());
        credentialRepresentation.setSecretData("secret");
        users.list().get(0).setCredentials(List.of(credentialRepresentation));

         */

        //headers
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        // body form-urlencoded
        MultiValueMap<String, String> mapForm= new LinkedMultiValueMap<>();
        mapForm.add("grant_type", "password");
        mapForm.add("client_id", "spring_boot_service_client");
        mapForm.add("client_secret", "zuMRjELewRtxplwdHQRJytXojPU7iTNV");
        mapForm.add("username", "janedoe");
        mapForm.add("password", "s3cr3t");

        // The request with header and body
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);

        try {
            ResponseEntity<Object> response = restTemplate.exchange(authorizationURI,
                    HttpMethod.POST,
                    request, Object.class);


            return "Bearer " + jsonParser.parseMap(Objects.requireNonNull(response.getBody()).toString())
                    .get("access_token")
                    .toString();
        }catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    @Test
    void getClientAccessToken() throws VerificationException {
        // headers
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        // body form-urlencoded
        MultiValueMap<String, String> mapForm= new LinkedMultiValueMap<>();
        mapForm.add("grant_type", "client_credentials");
        mapForm.add("client_id", "spring_boot_service_client");
        mapForm.add("client_secret", "zuMRjELewRtxplwdHQRJytXojPU7iTNV");

        KeyCloakToken keycloakResponse = this.callKeyCloak(headers, mapForm);

        // get the access token to verify
        String retrievedAccessToken = keycloakResponse.accessToken;
        Assertions.assertNotNull(retrievedAccessToken);

        // parse the received access-token
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(retrievedAccessToken, AccessToken.class);
        verifier.parse();

        // check for the custom claim
        AccessToken accessToken = verifier.getToken();
        //String customClaimValue = (String) accessToken.getOtherClaims().get(TestOidcProtocolMapper.CUSTOM_CLAIM_NAME);
        //System.out.printf("Custom Claim name %s=%s%n", TestOidcProtocolMapper.CUSTOM_CLAIM_NAME, customClaimValue);
        //assertThat(customClaimValue, notNullValue());
        assertEquals("service-account-spring_boot_service_client", accessToken.getPreferredUsername());



        String test = "test";


    }

    private KeyCloakToken callKeyCloak(HttpHeaders headers, MultiValueMap<String, String> mapForm) {

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);

        ResponseEntity<KeyCloakToken> response = restTemplate.exchange(authorizationURI,
                HttpMethod.POST,
                request, KeyCloakToken.class);
        return response.getBody();
    }


    @Test
    void testGetBearerTokenSuccess() throws URISyntaxException {
        String bearer = getBearerToken();

        String test = "test";
    }

    @Test
    public void shouldDeployExtensionWithReuse1() throws Exception {
        simpleOidcProtocolMapperTest();
    }

    @Test
    public void shouldDeployExtensionWithReuse2() throws Exception {
        simpleOidcProtocolMapperTest();
    }

    @Test
    public void shouldDeployExtensionWithReuse3() throws Exception {
        simpleOidcProtocolMapperTest();
    }

    private void simpleOidcProtocolMapperTest() throws Exception {

        Keycloak keycloakClient = KEYCLOAK.getKeycloakAdminClient();

        keycloakClient.tokenManager().grantToken();

        keycloakClient.tokenManager().refreshToken();
        AccessTokenResponse tokenResponse = keycloakClient.tokenManager().getAccessToken();

        // parse the received access-token
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenResponse.getToken(), AccessToken.class);
        verifier.parse();

        // check for the custom claim
        AccessToken accessToken = verifier.getToken();
        //String customClaimValue = (String) accessToken.getOtherClaims().get(TestOidcProtocolMapper.CUSTOM_CLAIM_NAME);
        //System.out.printf("Custom Claim name %s=%s%n", TestOidcProtocolMapper.CUSTOM_CLAIM_NAME, customClaimValue);
        //assertThat(customClaimValue, notNullValue());
        //assertThat(customClaimValue, startsWith("testdata:"));
    }


    private record KeyCloakToken(String accessToken, int expiresIn, String tokenType) {

            @JsonCreator
            private KeyCloakToken(@JsonProperty("access_token") final String accessToken,
                                  @JsonProperty("expires_in") final int expiresIn,
                                  @JsonProperty("token_type") final String tokenType) {
                this.accessToken = accessToken;
                this.expiresIn = expiresIn;
                this.tokenType = tokenType;
            }
        }
}
