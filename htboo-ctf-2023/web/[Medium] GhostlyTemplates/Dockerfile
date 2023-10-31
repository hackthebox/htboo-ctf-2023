FROM alpine:3.18.3

# Install packages
RUN apk --no-cache add supervisor make musl-dev gcc go

# Add go to PATH
RUN export GOPATH=/root/go
RUN export PATH=${GOPATH}/bin:/usr/local/go/bin:$PATH
RUN export GOBIN=$GOROOT/bin
RUN mkdir -p ${GOPATH}/src ${GOPATH}/bin
RUN export GO111MODULE=on

# Copy flag
COPY flag.txt /flag.txt

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Build server executable
RUN go build -o blogify main.go

# Expose the port
EXPOSE 1337

# Copy entrypoint
COPY --chown=root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]