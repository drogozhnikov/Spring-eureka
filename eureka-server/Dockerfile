FROM openjdk:17 as build
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} EurekaServerApplication.jar
ENTRYPOINT ["java","-jar","EurekaServerApplication.jar"]
