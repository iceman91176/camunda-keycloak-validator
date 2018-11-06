# Camunda JWT REST API - Keycloak JWT Validator

This is a Keycloak JWT Validator for the excellent **JWT REST API Validation Provider** by Stephen Ott/DigitalState (https://github.com/DigitalState/camunda-rest-jwt-authentication)

# How it works
The token which contains the username & camunda-groups is passed to the validator-class **KeycloakValidator**. This class has to be configured in the Servlet-WebFilter (see example below).

The validator verfies a RSA-signed keycloak-token and extracts, username, camunda-groups & camunda-tenants.

The validator requires 2 configuration-parameters which are passed as ENVIRONMENT-Variables

1. `KEYCLOAK_SERVER_URL` : The Base-URL for keycloak, eg: https://mykcinstance.topsecret.org/auth 
2. `KEYCLOAK_REALM_ID` : Keycloak Realm-ID

Since the validator gets the public key for decoding the token from the keycloak certificate-endpoint )**KEYCLOAK_SERVER_URL/realm/KEYCLOAK_REALM_ID/protocol/openid-connect/certs**) it is required, that

1. the certificate endpoint is reachable
2. if you are using a private CA to sig your certificates, you have to add your CA-Certs to the Java-Truststore

#How to setup

Prepare Keycloak

Simple setup that grants admin-privileges to camunda. JSON-Files that can be imported are located in examples/keycloak-config

1. Create a client scope that return a claim with the roles a user has assigned. Claim-Name must be groupIds
2. Optional - return another claim with a list of tenant-ids
3. Create a role camunda-admins (Realm-role)
4. Create a user and assign the role camunda-admins to it

Run Camunda as docker container

An example Docker-compose / dockerfile is included in examples/docker/tomcat . For other deployments follow https://github.com/DigitalState/camunda-rest-jwt-authentication/blob/master/README.md. 


1. Build camunda-rest-jwt-authentication and copy target/camunda-rest-api-jwt-authentication-VERSION-jar-with-dependencies.jar to examples/docker/tomcat/docker/camunda/webapps/engine-rest/WEB-INF/lib/
2. Build camunda-keycloak-validator and copy target/camunda-keycloak-validator-VERSION-jar-with-dependencies.jar to examples/docker/tomcat/docker/camunda/webapps/engine-rest/WEB-INF/lib/
3. CD to examples/docker/tomcat/
4. If you use a private CA take a look at the Dockerfile for including CA-Certs in java truststore
5. Modify docker-compose.yml to adjust Ports/Enviroment Variables 
6. ```docker-compose up```
7. Create admin-user with camunda-webfrontend
8. Try to exectute a REST-Operation without/with Token ;-)

