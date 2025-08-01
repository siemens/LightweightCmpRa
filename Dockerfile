FROM maven:3.9.11-amazoncorretto-17-debian AS build
COPY . /app
WORKDIR /app

# Clone and build custom CmpRaComponent that supports RAT
RUN --mount=type=secret,id=netrc,dst=/root/.netrc \
    apt-get update && apt-get install -y git && \
    git clone --branch RAT_integration https://code.siemens.com/ct-rda-cst-ses-de/remote-attestation/base-functionality/CmpRaComponent.git /cmpra && \
    cd /cmpra && mvn clean install -DskipTests -Ddependency-check.skip=true -Dmaven.javadoc.skip=true -Dmaven.source.skip=true -Dgpg.skip

# Use the freshly built CmpRaComponent with lightweightcmpra
RUN mvn clean install -DskipTests -Ddependency-check.skip=true -Dmaven.javadoc.skip=true -Dmaven.source.skip=true && \
    mvn dependency:copy-dependencies -DoutputDirectory=target/lib


FROM eclipse-temurin:17.0.15_6-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar ./app.jar
COPY --from=build /app/target/lib ./lib

# for now we bake in all the configuration files, certificates and keys
COPY --from=build /app/src/test/java/com/siemens/pki/lightweightcmpra/test/config /etc/ra

EXPOSE 6666
CMD ["java", "-jar", "app.jar", "/etc/ra/EnrollmentConfigWithRAT.yaml"]
