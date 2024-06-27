FROM adoptopenjdk/openjdk11:jdk-11.0.12_7
ARG JAR_FILE=build/libs/femida-ms-agw.jar
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Dspring.profiles.active=pits", "-jar","/app.jar"]