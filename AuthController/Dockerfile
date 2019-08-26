FROM openjdk:8-jdk-alpine
VOLUME /tmp
COPY target/AuthController-0.0.1-SNAPSHOT.jar AuthController.jar
EXPOSE 8080
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/AuthController.jar"]