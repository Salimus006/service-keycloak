package com.example.service.keycloak;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.*;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.common.VerificationException;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import static org.hamcrest.Matchers.notNullValue;

public class OtherTests {

    public static final String TEST_REALM_JSON = "/test-realm.json";
    //public static final String TEST_REALM_JSON = "keycloak/realm-export.json";
    private static final JacksonJsonParser jsonParser = new JacksonJsonParser();
    private static final RestTemplate restTemplate = new RestTemplate();
    //public static final KeycloakContainer KEYCLOAK = new KeycloakContainer().withRealmImportFile(TEST_REALM_JSON);
    public static final KeycloakContainer KEYCLOAK = new KeycloakContainer().withAdminUsername("admin").withAdminPassword("admin");

    private static URI authorizationURI;
            /*http://localhost:53099/realms/spring_boot_service/protocol/openid-connect/token
            new KeycloakContainer()
            .withRealmImportFile(TEST_REALM_JSON)
            // this would normally be just "target/classes"
            .withProviderClassesFrom("target/test-classes")
            // this enables KeycloakContainer reuse across tests
            .withReuse(true);

             */



    @BeforeAll
    public static void beforeAll() throws URISyntaxException {
        KEYCLOAK.start();

        Keycloak keycloakClient = KEYCLOAK.getKeycloakAdminClient();

        RealmResource realm = keycloakClient.realm("master");
        //ClientRepresentation client = realm.clients().findByClientId("master").get(0);

        //configureCustomOidcProtocolMapper(realm, client);

        authorizationURI = new URIBuilder(KEYCLOAK.getAuthServerUrl() + "/realms/master/protocol/openid-connect/token").build();

    }

    @AfterAll
    public static void afterAll() {
        KEYCLOAK.stop();
    }

    static void configureCustomOidcProtocolMapper(RealmResource realm, ClientRepresentation client) {

        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL); // openid-connect
        //mapper.setProtocolMapper(TestOidcProtocolMapper.ID);
        mapper.setName("test-mapper");
        Map<String, String> config = new HashMap<>();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        mapper.setConfig(config);

        realm.clients().get(client.getId()).getProtocolMappers().createMapper(mapper).close();
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
        Assertions.assertEquals("service-account-spring_boot_service_client", accessToken.getPreferredUsername());



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
