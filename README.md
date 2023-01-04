# Home Auth Service 
Home Stack Authorization Service

## Functionality
- Validate Google Openid Token

### How to run
````
java -jar target/home-auth-service-1.0.0-SNAPSHOT.jar --oauth.google.client.id=
````

#### Build
1. Maven Package
   ````
   mvn clean package
   ````
2. Docker Build, Push & Run
   ````
   docker build -t alokkusingh/home-auth-service:latest -t alokkusingh/home-auth-service:1.0.0 --build-arg JAR_FILE=target/home-auth-service-1.0.0-SNAPSHOT.jar .
   ````
   ````
   docker push alokkusingh/home-auth-service:latest
   ````
   ````
   docker push alokkusingh/home-auth-service:1.0.0
   ````
   ````
   docker run -d -p 8081:8081 --rm --name home-auth-service alokkusingh/home-auth-service --oauth.google.client.id=
   ````
   
### Manual commands
````
docker run -it --entrypoint /bin/bash -p 8081:8081 --rm --name home-auth-service alokkusingh/home-auth-service
````
````
java -Djava.security.egd=file:/dev/urandom -Doauth.google.client.id= -jar /opt/app.jar
````
````
docker run -p 8081:8081 --rm --name home-etl-service alokkusingh/home-etl-service \
--java.security.egd=file:/dev/urandom --oauth.google.client.id= 
````