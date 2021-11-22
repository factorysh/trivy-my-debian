FROM bearstech/python-dev:3.9 as dev

COPY . /opt/trivy-my-debian/

RUN cd /opt/trivy-my-debian/ \
        && make venv

FROM bearstech/python:3.9

RUN useradd -ms /bin/bash trivy

COPY --from=dev /opt/trivy-my-debian/ /opt/trivy-my-debian/

USER trivy
WORKDIR /opt/trivy-my-debian/
EXPOSE 8000
CMD ["/opt/trivy-my-debian/venv/bin/uvicorn", "--host", "0.0.0.0", "main:app"]
