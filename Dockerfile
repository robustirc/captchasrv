# Start with busybox, but with libc.so.6
FROM busybox:glibc

MAINTAINER Michael Stapelberg <michael@robustirc.net>

# So that we can run as unprivileged user inside the container.
RUN echo 'nobody:x:99:99:nobody:/:/bin/sh' >> /etc/passwd

USER nobody

ADD ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ADD captchasrv /usr/bin/captchasrv

EXPOSE 8080

ENTRYPOINT ["/usr/bin/captchasrv"]
