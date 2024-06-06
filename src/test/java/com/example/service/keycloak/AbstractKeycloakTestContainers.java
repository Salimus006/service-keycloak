package com.example.service.keycloak;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class AbstractKeycloakTestContainers {
    private static final KeycloakContainer keycloak;

    static {
        keycloak = new KeycloakContainer().withRealmImportFile("keycloak/realm-export.json");
        keycloak.start();
    }

    static {

    }
    @DynamicPropertySource
    static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> keycloak.getAuthServerUrl() + "/realms/spring_boot_service");
    }

    public String requestToken() throws URISyntaxException {
        URI authorizationURI = new URIBuilder(keycloak.getAuthServerUrl() + "/realms/spring_boot_service/protocol/openid-connect/token").build();
        RestTemplate restTemplate = new RestTemplate();

        //headers
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        // body form-urlencoded
        MultiValueMap<String, String> mapForm= new LinkedMultiValueMap<>();
        mapForm.add("grant_type", "password");
        mapForm.add("client_id", "spring_boot_service_client");
        mapForm.add("client_secret", "zuMRjELewRtxplwdHQRJytXojPU7iTNV");
        mapForm.add("username", "dody");
        mapForm.add("password", "1234");

        // The request with header and body
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);


        ResponseEntity<Object> response = restTemplate.exchange(authorizationURI,
                HttpMethod.POST,
                request, Object.class);

        JacksonJsonParser jsonParser = new JacksonJsonParser();
        return "Bearer " + jsonParser.parseMap(Objects.requireNonNull(response.getBody()).toString())
                .get("access_token")
                .toString();
    }
}
