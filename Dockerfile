FROM gradle:5.4.1-jdk11 as build

WORKDIR /trust-anchor
USER root
ENV GRADLE_USER_HOME ~/.gradle

COPY build.gradle build.gradle
RUN gradle install

COPY src/ src/

RUN gradle installDist

CMD ["gradle"]

FROM openjdk:11.0.3-slim-stretch

WORKDIR /trust-anchor

COPY --from=build /trust-anchor/build/install/trust-anchor .

ENTRYPOINT ["bin/trust-anchor"]
