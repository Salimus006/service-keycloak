package com.example.service.controllers;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.websocket.server.PathParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    private static final String GRANT_TYPE_PASSWORD = "password";
    private static final String GRANT_TYPE_REFRESH = "refresh_token";

    @Value("${keycloak.jwt-url}")
    private String keycloakJwtUrl;

    @Value("${keycloak.logout-url}")
    private String keycloakLogoutUrl;

    @Value("${keycloak.client-secret}")
    private String keycloakClientSecret;

    @Value("${keycloak.client-id}")
    private String keycloakClientId;
    private final RestTemplate restTemplate;

    public AuthenticationController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/info")
    @Operation(summary = "To get a converted JWT. (Must be authenticated)")
    public Authentication authentication(Authentication authentication) {
        return authentication;
    }

    @PostMapping("/authenticate/password")
    @Operation(summary = "(Keycloak login) Authenticate a user with userName and password")
    public ResponseEntity<Object> login(@PathParam("username") String userName, @PathParam("password") String password) {

        HttpEntity<MultiValueMap<String, String>> request = buildKeycloakPassWordRequest(userName, password);

        try {
            ResponseEntity<Object> response = this.restTemplate.exchange(keycloakJwtUrl,
                    HttpMethod.POST,
                    request, Object.class);

            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/authenticate/logout")
    @Operation(summary = "(Keycloak logout) Destroy user's session")
    public ResponseEntity<Object> logout(/*@RequestHeader("Authorization") String accessToken,*/
            @PathParam("access_token") String accessToken,
            @PathParam("refresh_token") String refreshToken) {
        // build keycloak http headers
        HttpHeaders headers = buildKeycloakHttpHeaders();
        headers.setBearerAuth(accessToken);

        // request body
        MultiValueMap<String, String> mapForm = buildKeycloakCommonForm(GRANT_TYPE_REFRESH);
        mapForm.add("client_id", this.keycloakClientId);
        mapForm.add("client_secret", this.keycloakClientSecret);
        mapForm.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);

        try {
            ResponseEntity<Object> response = this.restTemplate.exchange(keycloakLogoutUrl,
                    HttpMethod.POST,
                    request, Object.class);

            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/authenticate/refresh")
    @Operation(summary = "(Keycloak) Refresh the access token")
    ResponseEntity<Object> refreshAccessToken(@PathParam("refresh_token") String refreshToken) {

        HttpHeaders headers = buildKeycloakHttpHeaders();
        MultiValueMap<String, String> mapForm = buildKeycloakCommonForm(GRANT_TYPE_REFRESH);
        mapForm.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);

        try {
            ResponseEntity<Object> response = this.restTemplate.exchange(keycloakJwtUrl,
                    HttpMethod.POST,
                    request, Object.class);

            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }


    private HttpEntity<MultiValueMap<String, String>> buildKeycloakPassWordRequest(String userName, String password) {
        HttpHeaders headers = buildKeycloakHttpHeaders();

        MultiValueMap<String, String> mapForm = buildKeycloakCommonForm(GRANT_TYPE_PASSWORD);
        mapForm.add("username", userName);
        mapForm.add("password", password);

        return new HttpEntity<>(mapForm, headers);
    }

    private MultiValueMap<String, String> buildKeycloakCommonForm(String grantType) {
        MultiValueMap<String, String> mapForm= new LinkedMultiValueMap<>();
        mapForm.add("grant_type", grantType);
        mapForm.add("client_id", keycloakClientId);
        mapForm.add("client_secret", keycloakClientSecret);
        return mapForm;
    }

    private static HttpHeaders buildKeycloakHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");
        return headers;
    }
}
