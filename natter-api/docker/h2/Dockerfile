FROM curlimages/curl:7.66.0 AS build-env

ENV RELEASE h2-2019-10-14.zip
ENV SHA256 a72f319f1b5347a6ee9eba42718e69e2ae41e2f846b3475f9292f1e3beb59b01

WORKDIR /tmp

RUN echo "$SHA256  $RELEASE" > $RELEASE.sha256 && \
    curl -sSL https://www.h2database.com/$RELEASE -o $RELEASE && \
    sha256sum -b -c $RELEASE.sha256 && \
    unzip $RELEASE && rm -f $RELEASE

FROM gcr.io/distroless/java:11
WORKDIR /opt
COPY --from=build-env /tmp/h2/bin /opt/h2

USER 1000:1000

EXPOSE 9092
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/urandom", \
        "-cp", "/opt/h2/h2-1.4.200.jar", \
        "org.h2.tools.Server", "-tcp", "-tcpAllowOthers"]