"""
See https://semver.org/
"""


class Version:
    major = 0
    minor = 0
    patch = "0"
    pre_release = ""
    build = ""

    def __str__(self):
        return "<Version %d %d %s - %s + %s >" % (
            self.major,
            self.minor,
            self.patch,
            self.pre_release,
            self.build,
        )

    def __init__(self, raw: str):
        slugs = raw.split("-", 2)
        if len(slugs) > 1:
            s = slugs[1].split("+", 2)
            self.pre_release = s[0]
            if len(s) > 1:
                self.build = s[1]
        else:
            s = raw.split("+", 2)
            if len(s) > 1:
                self.build = s[1]
        core = slugs[0].split(".", 3)
        self.major = int(core[0])
        if len(core) > 1:
            self.minor = int(core[1])
        if len(core) > 2:
            self.patch = core[2]

    def __eq__(self, other):
        return (
            self.major == other.major
            and self.minor == other.minor
            and self.patch == other.patch
            and self.pre_release == other.pre_release
        )

    def __ne__(self, other):
        return not self == other

    def __gt__(self, other):
        if self.major > other.major:
            return True
        if self.minor > other.minor:
            return True
        if self.patch > other.patch:
            return True
        if self.pre_release > other.pre_release:
            return True
        return False

    def __ge__(self, other):
        if self == other:
            return True
        return self > other


if __name__ == "__main__":
    for p in ["1.8.4-5", "1.8.4-5+deb10u1", "1.1.1d-0+deb10u6"]:
        v = Version(p)
        print(v)
    assert Version("1.8.4-5+deb10u1") >= Version("1.8.4-5")
