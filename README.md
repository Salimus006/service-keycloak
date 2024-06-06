# Demo for using spring boot application with keycloak OIDC

### Required env variables to start service
- KEYCLOAK_BASE_URL: http://localhost:8180
- KEYCLOAK_REALM_NAME: spring_boot_service
- KEYCLOAK_CLIENT_ID: spring_boot_service_client
- KEYCLOAK_CLIENT_SECRET: HmoDZeRFplZzcshdVKCF9IqczDj1cFBw

### Used Keycloak and postgres versions ([See docker-compose](./docker-compose.yml))
docker-compose start postgres container on port 5432 and keycloak on 8180
- Keycloak image : quay.io/keycloak/keycloak:24.0.5
- Postgres image postgres:14-alpine 

### Start the application
Before start spring boot application we must start keycloak server ans postgres db.
#### run docker compose to start keycloak and postgres
```console
docker-compose -f docker-compose.yml up
```
#### run spring boot application
set your env variables in pom.xml for (KEYCLOAK_BASE_URL, KEYCLOAK_REALM_NAME, KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET)

Then run 
```console
mvn spring-boot:run
```
### Postman section 
- Go to postman and import ([keycloak_API.json](./keycloak/postman/keycloak_API.json))


### Lunch and test swagger API 
Go to the [Swagger](http://localhost:8081/swagger-ui/index.html) to test the spring boot application





