import ijson
import json


DEBIANS = {"12": "bookworm", "11": "bullseye", "10": "buster", "9": "stretch"}


class DB:
    "Debian CVE database"

    def __init__(self, path: str):
        self.f = open(path, "r")

    def cve(self, cve_id):
        "return data and package name from a CVE id"
        self.f.seek(0)
        for k, v in ijson.kvitems(self.f, ""):
            if cve_id in v:
                yield k, v[cve_id]


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

    def scan(self, trivy_data: dict):
        s = TrivyScan(trivy_data)
        debian = s.debian_version()
        for cve in s.cve():
            packages = []
            if cve["Severity"] in self.not_severity:
                continue
            for package, info in self.db.cve(cve["VulnerabilityID"]):
                if package in self.not_package:
                    continue
                ticket = info["releases"].get(debian)
                if ticket is None:
                    continue
                if not self.debian_minor and ticket is not None and ticket.get('nodsa') == 'Minor issue':
                    continue
                packages.append((cve, package, info, ticket))
            for package in packages:
                yield package


class TrivyScan:
    "Read a Trivy JSON dump"

    def __init__(self, data):
        if data["Metadata"]["OS"]["Family"] != "debian":
            raise Exception("Not a Debian")
        self.data = data
        self._n = None

    def debian_version(self):
        "Debian version name"
        if self._n is None:
            self._n = self.data["Metadata"]["OS"]["Name"].split(".")[0]
        return DEBIANS[self._n]

    def cve(self):
        for result in self.data["Results"]:
            if result["Type"] != "debian":
                continue
            for vulnerability in result["Vulnerabilities"]:
                yield vulnerability


if __name__ == "__main__":
    import os, sys
    from pprint import pprint

    td = TrivyDebian(DB(os.getenv("DB")),
                     not_package=["vim", "systemd"],
                     not_severity=["LOW"],
                     debian_minor=False)
    for cve, package, info, ticket in td.scan(json.load(sys.stdin)):
        print("#", cve["VulnerabilityID"])
        print("##", package)
        print("scope:", info.get("scope", "?"))
        print("### Debian")
        pprint(ticket)
        print("### Trivy")
        pprint(cve)
        print("\n")
