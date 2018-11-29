FROM camunda/camunda-bpm-platform:tomcat-7.9.0

RUN rm -r webapps/camunda-invoice

COPY docker/camunda/conf/bpm-platform.xml /camunda/conf/bpm-platform.xml

COPY docker/camunda/webapps/engine-rest/WEB-INF/lib/camunda-rest-api-jwt-authentication-v0.5-jar-with-dependencies.jar /camunda/webapps/engine-rest/WEB-INF/lib/camunda-rest-api-jwt-authentication-v0.5-jar-with-dependencies.jar
COPY docker/camunda/webapps/engine-rest/WEB-INF/web.xml /camunda/webapps/engine-rest/WEB-INF/web.xml

# Example usage of a standalone jar with the keycloak jwt validator class that is extended from the camunda-rest-api-jwt-authentication jar.
COPY docker/camunda/webapps/engine-rest/WEB-INF/lib/camunda-keycloak-validator-1.0.0-jar-with-dependencies.jar /camunda/webapps/engine-rest/WEB-INF/lib/camunda-keycloak-validator-1.0.0-jar-with-dependencies.jar

#Example of adding additional CA-Certs to Java-Truststore
USER root
COPY docker/certs/witca.pem /etc/ssl/certs/java/witca.pem
COPY docker/certs/intermediateca.pem /etc/ssl/certs/java/intermediateca.pem
RUN \
    cd /etc/ssl/certs/java \
    && keytool -keystore cacerts -storepass changeit -noprompt -trustcacerts -importcert -alias witca -file witca.pem \
    && keytool -keystore cacerts -storepass changeit -noprompt -trustcacerts -importcert -alias intermediateca -file intermediateca.pem

