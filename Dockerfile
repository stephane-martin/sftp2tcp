FROM golang:1.10 AS builder
MAINTAINER stephane.martin@soprasteria.com
WORKDIR $GOPATH/src/github.com/stephane-martin/sftp2tcp
COPY . ./
RUN make release
RUN cp sftp2tcp /

FROM debian:stretch
ENV TZ=Europe/Paris
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN useradd --create-home --shell /bin/bash --home-dir /home/sftp2tcp --user-group --uid 502 sftp2tcp
COPY --from=builder --chown=sftp2tcp:sftp2tcp /sftp2tcp /home/sftp2tcp/
COPY --chown=sftp2tcp:sftp2tcp privatekey.rsa /home/sftp2tcp
COPY tini /
RUN chmod a+x /tini
RUN chmod a+x /home/sftp2tcp/sftp2tcp

EXPOSE 2222/tcp

ENTRYPOINT ["/tini", "--"]
CMD ["/home/sftp2tcp/sftp2tcp","--listenport","2222","--privatekey","/home/sftp2tcp/privatekey.rsa","proxy"]

