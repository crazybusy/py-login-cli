from subprocess import run
import sys

print(sys.argv)
if sys.argv:
	run (sys.argv[1:])


