FROM eu.gcr.io/sanluna-gwr/maven-base-build:latest as build
COPY pom.xml /home/app/pom.xml
COPY ./src /home/app/src/
RUN mvn -f /home/app/pom.xml package -B

FROM openjdk:8-jre-alpine
MAINTAINER Alexander_Lundberg_Santos

RUN apk add --no-cache bash
COPY --from=build home/app/target/gwr-authentication-service-1.0.jar app.jar
RUN sh -c 'touch /app.jar'
ENTRYPOINT ["/usr/bin/java"]
CMD ["-jar", "/app.jar"]
EXPOSE 18100