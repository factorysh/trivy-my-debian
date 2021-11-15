from version import Version


def test_sort():
    for p in ["1.8.4-5", "1.8.4-5+deb10u1", "1.1.1d-0+deb10u6"]:
        v = Version(p)
        print(v)
    assert Version("1.8.4-5+deb10u1") >= Version("1.8.4-5")
