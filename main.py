from typing import Optional, Dict, List
import logging
import os

from fastapi import FastAPI

from debian import DB, TrivyDebian, Trivy


td = TrivyDebian(
    DB(os.getenv("DB"), os.getenv("DB_CACHE", "./debian.db")),
    not_package=["vim", "systemd", "rsyslog"],
    not_severity=["LOW"],
    debian_minor=False,
)
td.logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

app = FastAPI(on_startup=[])


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.post("/trivy/debian")
async def debian(audit: Trivy):
    return [cve for cve, package, info, ticket in td.scan(audit)]
