import json
import pickle
import logging
import dbm
from pathlib import Path
from typing import List

import ijson
from pydantic import BaseModel

from version import Version


DEBIANS = {"12": "bookworm", "11": "bullseye", "10": "buster", "9": "stretch"}


class Trivy(BaseModel):
    SchemaVersion: int
    ArtifactName: str
    ArtifactType: str
    Metadata: dict
    Results: List[dict]


class DB:
    "Debian CVE database"

    def __init__(self, json_path: str, db_path: str):
        d = Path(db_path)
        j = Path(json_path)
        do_it = not d.is_file()
        if not do_it:
            do_it = j.stat().st_mtime > d.stat().st_mtime
        if do_it:
            f = open(json_path, "r")
            db = dbm.open(db_path, "c")
            for k, v in ijson.kvitems(f, ""):
                for cve_id, cve in v.items():
                    if cve_id in db:
                        data = pickle.loads(db[cve_id])
                    else:
                        data = []
                    data.append([k, cve])
                    db[cve_id] = pickle.dumps(data)
            f.close()
            db.close()
        self.db = dbm.open(db_path, "r")

    def cve(self, cve_id):
        "return data and package name from a CVE id"
        if cve_id in self.db:
            for cve in pickle.loads(self.db[cve_id]):
                yield tuple(cve)


class TrivyDebian:
    def __init__(self, db: DB, not_package=None, not_severity=None, debian_minor=True):
        self.db = db
        if not_package is None:
            self.not_package = []
        else:
            self.not_package = not_package
        if not_severity is None:
            self.not_severity = []
        else:
            self.not_severity = not_severity
        self.debian_minor = debian_minor
        self.logger = logging.getLogger(__name__)

    def scan(self, trivy_data: Trivy):
        s = TrivyScan(trivy_data)
        debian = s.debian_version()
        for cve in s.cve():
            packages = []
            if cve["Severity"] in self.not_severity:
                self.logger.info(cve["VulnerabilityID"], "to low :", cve["Severity"])
                continue
            for package, info in self.db.cve(cve["VulnerabilityID"]):
                if package in self.not_package:
                    (cve["VulnerabilityID"], "banned package :", package)
                    continue
                ticket = info["releases"].get(debian)
                if ticket is None:
                    self.logger.info(
                        cve["VulnerabilityID"], "without debian ticket :", package
                    )
                    continue
                if (
                    not self.debian_minor
                    and ticket is not None
                    and ticket.get("nodsa") == "Minor issue"
                ):
                    self.logger.info(cve["VulnerabilityID"], "debian minor :", package)
                    continue
                if cve["PkgName"] != package:
                    self.logger.info(
                        cve["VulnerabilityID"],
                        "debian name mismatch :",
                        cve["PkgName"],
                        "vs",
                        package,
                    )
                    continue
                if "FixedVersion" in cve and Version(
                    cve["InstalledVersion"]
                ) >= Version(cve["FixedVersion"]):
                    self.logger.info(
                        cve["VulnerabilityID"],
                        "better version :",
                        cve["InstalledVersion"],
                        "vs",
                        cve["FixedVersion"],
                    )
                    continue
                packages.append((cve, package, info, ticket))
            for package in packages:
                yield package


class TrivyScan:
    "Read a Trivy JSON dump"

    def __init__(self, data: Trivy):
        if data.Metadata["OS"]["Family"] != "debian":
            raise Exception("Not a Debian")
        self.data = data
        self._n = None

    def debian_version(self):
        "Debian version name"
        if self._n is None:
            self._n = self.data.Metadata["OS"]["Name"].split(".")[0]
        return DEBIANS[self._n]

    def cve(self):
        for result in self.data.Results:
            if result["Type"] != "debian":
                continue
            for vulnerability in result["Vulnerabilities"]:
                yield vulnerability


if __name__ == "__main__":
    import os, sys
    from pprint import pprint

    td = TrivyDebian(
        DB(os.getenv("DB"), "./debian.db"),
        not_package=["vim", "systemd", "rsyslog"],
        not_severity=["LOW"],
        debian_minor=False,
    )
    td.logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    for cve, package, info, ticket in td.scan(json.load(sys.stdin)):
        print("#", cve["VulnerabilityID"])
        print("##", package)
        print("scope:", info.get("scope", "?"))
        print("### Debian")
        pprint(ticket)
        print("### Trivy")
        pprint(cve)
        print("\n")
