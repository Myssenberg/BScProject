FROM mcr.microsoft.com/devcontainers/python:0-3.11

RUN pip install git+https://github.com/spring-epfl/zksk

WORKDIR /workspace

RUN mkdir /app
RUN printf "#!/bin/bash\nwhile true; do sleep 1000; done" >> /app/entrypoint.sh && chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
