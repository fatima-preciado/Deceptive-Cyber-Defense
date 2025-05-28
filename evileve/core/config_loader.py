import os
import yaml

_config = None

def load_config(path="config.yaml"):
    global _config
    if _config is None:
        with open(path, "r") as f:
            _config = yaml.safe_load(f)
    return _config

def get_path(key):
    cfg = load_config()
    raw_path = cfg.get("paths", {}).get(key)
    return os.path.expanduser(raw_path) if raw_path else None

def get_default(key):
    cfg = load_config()
    return cfg.get("defaults", {}).get(key)
