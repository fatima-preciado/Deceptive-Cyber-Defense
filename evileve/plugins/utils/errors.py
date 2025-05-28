import os

def safe_open(path, mode="r", encoding="utf-8"):
    try:
        return open(path, mode, encoding=encoding)
    except Exception as e:
        print(f"[error] Failed to open {path}: {e}")
        return None

def safe_write_jsonl(filepath, data):
    import json
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "a", encoding="utf-8") as f:
            json.dump(data, f)
            f.write("\n")
    except Exception as e:
        print(f"[error] Failed to write JSONL to {filepath}: {e}")

def ensure_file_exists(path, default_content=None):
    if not os.path.exists(path):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                if default_content:
                    f.write(default_content)
            print(f"[info] Created fallback file: {path}")
        except Exception as e:
            print(f"[error] Could not create file {path}: {e}")
