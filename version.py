class Version:
    major = 0
    minor = 0
    patch = ""

    def __str__(self):
        return "<Version %d %d %s >" % (self.major, self.minor, self.patch)

    def __init__(self, raw: str):
        slugs = raw.split(".", 3)
        self.major = int(slugs[0])
        if len(slugs) > 1:
            self.minor = int(slugs[1])
        if len(slugs) > 2:
            self.patch = slugs[2]


if __name__ == "__main__":
    for p in ["1.8.4-5", "1.8.4-5+deb10u1", "1.1.1d-0+deb10u6"]:
        v = Version(p)
        print(v)
