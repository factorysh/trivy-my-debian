import ijson
import json


DEBIANS = {"12": "bookworm", "11": "bullseye", "10": "buster", "9": "stretch"}


class DB:
    def __init__(self, path: str):
        self.f = open(path, "r")

    def cve(self, name):
        self.f.seek(0)
        for k, v in ijson.kvitems(self.f, ""):
            if name in v:
                return k, v[name]


class TrivyDebian:
    def __init__(self, data):
        if data["Metadata"]["OS"]["Family"] != "debian":
            raise Exception("Not a Debian")
        self.data = data
        self._n = None

    def name(self):
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

    d = DB(os.getenv("DB"))
    td = TrivyDebian(json.load(sys.stdin))
    name = td.name()
    for cve in td.cve():
        package, info = d.cve(cve["VulnerabilityID"])
        pprint(cve)
        if name in info["releases"]:
            pprint(info["releases"][name])
        else:
            pprint(info["releases"])
        print("\n\n")
