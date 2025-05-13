#!/usr/bin/python3
from time import sleep

import stapsdt

provider = stapsdt.Provider("examplepythonapp")
probe = provider.add_probe("firstProbe", stapsdt.ArgTypes.uint64, stapsdt.ArgTypes.int32)
provider.load()

while True:
    print("Firing probe...")
    probe.fire("firstProbeFire")
    sleep(1)