FROM openjdk:11 as build
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} SpringAuthorization.jar
ENTRYPOINT ["java","-jar","SpringAuthorization.jar"]
