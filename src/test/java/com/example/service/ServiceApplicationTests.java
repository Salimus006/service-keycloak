package com.example.service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(
		properties = {
				"spring.jpa.hibernate.ddl-auto=validate",
				"liquibase.enabled=false"
		}
)
class ServiceApplicationTests {

	@Test
	void contextLoads() {
	}

}
