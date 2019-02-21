import os
import json

with open(os.path.join('data/Location', 'voting_res.json'), 'r', errors='ignore') as infile:
    r = json.load(infile)
    print(r)
