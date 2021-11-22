FROM bearstech/python-dev:3.9 as dev

COPY . /opt/trivy-my-debian/

RUN cd /opt/trivy-my-debian/ \
        && make venv

FROM bearstech/python:3.9

RUN useradd -ms /bin/bash trivy \
        && mkdir /data \
        && chown trivy /data \
        && chmod 775 /data

RUN apt-get update && apt-get install -y \
        ca-certificates \
    &&  apt-get clean \
    &&  rm -rf /var/lib/apt/lists/*

COPY --from=dev /opt/trivy-my-debian/ /opt/trivy-my-debian/

USER trivy
WORKDIR /opt/trivy-my-debian/
EXPOSE 8000
ENV DB=/data/debian_cve.json \
    DB_CACHE=/data/debian.db
ENTRYPOINT ["/opt/trivy-my-debian/entrypoint.sh"]
CMD ["/opt/trivy-my-debian/venv/bin/uvicorn", "--host", "0.0.0.0", "main:app"]
