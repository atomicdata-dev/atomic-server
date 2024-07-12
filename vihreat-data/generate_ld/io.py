import json


_base_dir = "json"


def write(R, name):
    with open(f"{_base_dir}/{name}.json", "w") as f:
        f.write(json.dumps(R, indent=2))
