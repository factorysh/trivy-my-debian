import ijson
import json


class DB:
    def __init__(self, path: str):
        self.f = open(path, 'r')

    def cve(self, name):
        self.f.seek(0)
        for k, v in ijson.kvitems(self.f, ''):
            if name in v:
                return k, v[name]


class TrivyDebian:
    def __init__(self, data):
        self.data = data

    def cve(self):
        for result in self.data['Results']:
            if result['Type'] != 'debian':
                continue
            for vulnerability in result['Vulnerabilities']:
                yield vulnerability['VulnerabilityID']





if __name__ == "__main__":
    import os, sys
    d = DB(os.getenv('DB'))
    td = TrivyDebian(json.load(sys.stdin))
    for cve in td.cve():
        dcve = d.cve(cve)
        print(cve, dcve)
