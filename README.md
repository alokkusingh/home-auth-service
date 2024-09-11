# Home Auth Service 
Home Stack Authorization Service

## Functionality
- Validate Google Openid Token

### How to run
````
java -jar target/home-auth-service-1.0.0-SNAPSHOT.jar --oauth.google.client.id=
````

#### Build
```shell
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home
export PATH=$JAVA_HOME/bin:$PATH
```
1. Maven Package
   ```shell
   mvn clean package -DskipTests
   ```
2. Docker Build, Push & Run
   ```shell
   docker build -t alokkusingh/home-auth-service:latest -t alokkusingh/home-auth-service:2.0.0 --build-arg JAR_FILE=target/home-auth-service-2.0.0-SNAPSHOT.jar .
   ```
   ```shell
   docker push alokkusingh/home-auth-service:latest
   ```
   ```shell
   docker push alokkusingh/home-auth-service:2.0.0
   ```
   ```shell
   docker run -d -p 8081:8081 --rm --name home-auth-service alokkusingh/home-auth-service --oauth.google.client.id=
   ```
   
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