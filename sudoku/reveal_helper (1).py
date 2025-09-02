#!/usr/bin/env python3
import json, sys
if len(sys.argv) != 3:
    print("usage: reveal_helper.py <a> <b>", file=sys.stderr)
    sys.exit(1)
a = int(sys.argv[1]); b = int(sys.argv[2])
with open("mapping.json") as f:
    m = json.load(f)
ra = m[str(a)]; rb = m[str(b)]
print(json.dumps([{"commitment": ra["commitment"], "color_name": ra["color_name"], "nonce": ra["nonce"]},
                  {"commitment": rb["commitment"], "color_name": rb["color_name"], "nonce": rb["nonce"]}]))
