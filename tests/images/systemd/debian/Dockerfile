# Tier 2 systemd-enabled image for service.* suites (plans/testing.md).
# Built in CI from the digest-pinned base image; never pulled prebuilt.
FROM debian@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends systemd systemd-sysv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY statekit-test.service /etc/systemd/system/statekit-test.service
COPY statekit-test-second.service /etc/systemd/system/statekit-test-second.service
# Enable without a running init by linking into the wants directory.
RUN mkdir -p /etc/systemd/system/multi-user.target.wants \
    && ln -s ../statekit-test.service \
        /etc/systemd/system/multi-user.target.wants/statekit-test.service

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
