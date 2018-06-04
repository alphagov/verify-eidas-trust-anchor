FROM gradle:4.7.0-jdk8 as build

WORKDIR /trust-anchor
USER root
ENV GRADLE_USER_HOME ~/.gradle

COPY build.gradle build.gradle
RUN gradle install

COPY src/ src/

RUN gradle installDist

CMD ["gradle"]

FROM openjdk:8u171-jre

WORKDIR /trust-anchor

COPY --from=build /trust-anchor/build/install/trust-anchor .

ENTRYPOINT ["bin/trust-anchor"]
