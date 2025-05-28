import os
import json
import uuid
import random
from core.psychology import update_suspicion_and_utility

PROFILE_DIR = os.path.expanduser("~/.evilEVE/attackers")
PROFILE_SCHEMA_VERSION = "1.0.0"  # Increment this if structure changes


def generate_attacker_profile(name, seed=None):
    if seed is not None:
        random.seed(seed)

    attacker_id = str(uuid.uuid4())

    initial = {
        "confidence": random.randint(0, 5),
        "frustration": random.randint(0, 5),
        "self_doubt": random.randint(0, 5),
        "confusion": random.randint(0, 5)
    }

    profile = {
        "id": attacker_id,
        "name": name,
        "schema_version": PROFILE_SCHEMA_VERSION,
        "initial_psychology": initial,
        "current_psychology": initial.copy(),
        "skill": random.randint(0, 5),
        "memory_graph": {},
        "tools_used": [],
        "failed_attempts": {},
        "metrics": {},
        "seed": seed
    }

    update_suspicion_and_utility(profile)
    return profile


def load_or_create_profile(name, seed=None, preserve_psych_baseline=True, initialize_skill=True):
    os.makedirs(PROFILE_DIR, exist_ok=True)
    path = os.path.join(PROFILE_DIR, f"{name}.json")

    if os.path.exists(path):
        with open(path) as f:
            profile = json.load(f)

        # Schema validation
        if "schema_version" not in profile:
            print(f"[!] WARNING: Profile '{name}' missing schema_version. Regenerating...")
            profile = generate_attacker_profile(name, seed)
        elif profile["schema_version"] != PROFILE_SCHEMA_VERSION:
            print(f"[!] WARNING: Profile '{name}' is outdated (version {profile['schema_version']}). Consider regenerating.")
            # Optionally: add auto-migration logic here

        # Re-initialize psychology baseline
        if preserve_psych_baseline:
            if "initial_psychology" in profile:
                profile["current_psychology"] = profile.get("current_psychology", profile["initial_psychology"].copy())

        if initialize_skill and "skill" not in profile:
            profile["skill"] = random.randint(0, 5)

        update_suspicion_and_utility(profile)
        return profile

    # Profile didn't exist — generate fresh
    profile = generate_attacker_profile(name, seed)
    save_profile(profile, preserve_baseline=True)
    return profile


def save_profile(profile, preserve_baseline=True, adjust_skill=True):
    if adjust_skill:
        false_actions = profile.get("metrics", {}).get("false_actions", 0)
        time_wasted = profile.get("metrics", {}).get("time_wasted", 0)
        successes = len(profile.get("tools_used", []))

        total_uses = false_actions + (time_wasted // 2) + successes
        if total_uses > 0:
            success_ratio = successes / total_uses
            if success_ratio > 0.6 and profile["skill"] < 5:
                profile["skill"] += 1
            elif success_ratio < 0.2 and profile["skill"] > 0:
                profile["skill"] -= 1

    if preserve_baseline:
        if "initial_psychology" in profile and "current_psychology" in profile:
            for trait in profile["initial_psychology"]:
                profile["initial_psychology"][trait] = profile["initial_psychology"][trait]

    # Remove unserializable object before saving
    profile.pop("current_state_obj", None)

    profile["schema_version"] = PROFILE_SCHEMA_VERSION  # Ensure schema stays up to date

    path = os.path.join(PROFILE_DIR, f"{profile['name']}.json")
    with open(path, "w") as f:
        json.dump(profile, f, indent=2)


