#!/usr/bin/env python3

# Make sure check.pyc is in working directory
import check
from z3 import *

s = Solver()
flag = [BitVec(f"flag_{i}", 8) for i in range(len(check.CHECK))]

trans = check.transform(flag)
for i in range(len(flag)):
	s.add(trans[i] == check.CHECK[i])

print(s.check())
m = s.model()

print(''.join(chr(m[f].as_long()) for f in flag))
