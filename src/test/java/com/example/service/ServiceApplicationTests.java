package com.example.service;

import com.example.service.controllers.AbstractKeycloakTest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)

@TestPropertySource(
		properties = {
		"keycloak.client-realm=spring_boot_service",
				"keycloak.client-id=spring_boot_service_client",
				"keycloak.client-secret=HmoDZeRFplZzcshdVKCF9IqczDj1cFBw"}
)
class ServiceApplicationTests extends AbstractKeycloakTest {

	@DynamicPropertySource
	static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
		registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> KEYCLOAK.getAuthServerUrl() + "/realms/"+REALM_NAME );
		registry.add("keycloak.base-url", KEYCLOAK::getAuthServerUrl);
	}
	@Test
	void contextLoads() {
	}
}
