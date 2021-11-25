from typing import Optional, Dict, List
import logging
import os

from fastapi import FastAPI
from pydantic_yaml import YamlModel

from debian import DB, TrivyDebian, Trivy


class Config(YamlModel):
    not_package: List[str]
    not_severity: List[str]
    debian_minor: bool


cfg = os.getenv("CONFIG")
if cfg is None:
    config = Config(
        not_package=["vim", "systemd", "rsyslog"],
        not_severity=["LOW"],
        debian_minor=False
    )
else:
    config = Config.parse_raw(open(cfg, 'r'))

logging.info("config", config)

td = TrivyDebian(
    DB(os.getenv("DB", "./debian_cve.json"), os.getenv("DB_CACHE", "./debian.db")),
    not_package=config.not_package,
    not_severity=config.not_severity,
    debian_minor=config.debian_minor,
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
