FROM openjdk:17 as build
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} ApiGatewayApplication.jar
ENTRYPOINT ["java","-jar","ApiGatewayApplication.jar"]
