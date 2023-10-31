FROM python:3.9-slim-buster 

RUN apt update
RUN apt install -y supervisor

# Install dependencies
RUN pip install prettytable


# Add application
WORKDIR /challenge
COPY challenge/server.py .
COPY challenge/secret.py .

# Setup superivsord
ADD config/supervisord.conf /etc/

# Expose the port
EXPOSE 1337

# Switch to use a non-root user from here on
USER nobody

# Start the python application
CMD /usr/bin/supervisord -c /etc/supervisord.conf