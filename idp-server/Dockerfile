# Start from an OpenJDK image
FROM eclipse-temurin:17-jre as runtime

# Set a working directory
WORKDIR /app

# Copy the jar built from Maven
COPY target/auth-*.jar app.jar

# Expose the port your app runs on
EXPOSE 9000

# Run the Spring Boot app
ENTRYPOINT ["java", "-jar", "app.jar"]
