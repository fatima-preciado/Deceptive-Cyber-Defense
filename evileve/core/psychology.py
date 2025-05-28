# core/psychology.py

import json
import csv
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class CognitiveState:
    confidence: float
    self_doubt: float
    confusion: float
    frustration: float
    surprise: float
    suspicion: float
    utility: float

def apply_correlations(profile):
    """
    Adjusts psychological traits based on known Tularosa correlation effects.
    """
    traits = profile.get("current_psychology", {})

    frustration = traits.get("frustration", 2.5)
    self_doubt = traits.get("self_doubt", 2.5)
    confusion = traits.get("confusion", 2.5)
    confidence = traits.get("confidence", 2.5)
    surprise = traits.get("surprise", 2.5)

    # Apply Tularosa-based correlation modeling
    confusion += 0.3 * (frustration - 2.5)
    surprise += 0.3 * (frustration - 2.5)
    confidence -= 0.3 * (self_doubt - 2.5)

    # Clamp all traits to 0.0–5.0 scale
    traits["confusion"] = round(max(0.0, min(5.0, confusion)), 2)
    traits["surprise"] = round(max(0.0, min(5.0, surprise)), 2)
    traits["confidence"] = round(max(0.0, min(5.0, confidence)), 2)

def update_suspicion_and_utility(profile):
    traits = profile.get("current_psychology", {})

    # Default values are mid-scale (1–5 Likert)
    frustration = traits.get("frustration", 2.5)
    confusion = traits.get("confusion", 2.5)
    self_doubt = traits.get("self_doubt", 2.5)
    confidence = traits.get("confidence", 2.5)
    surprise = traits.get("surprise", 2.5)

    # Apply Tularosa-style weighted suspicion model
    suspicion = round((
        0.3 * frustration +
        0.3 * confusion +
        0.2 * self_doubt +
        0.2 * (5 - confidence)
    ), 2)

    # Utility = confidence - perceived risk
    perceived_risk = profile.get("perceived_risk", 2.5)
    utility = round(confidence - perceived_risk, 2)

    # Store in profile
    profile["suspicion"] = suspicion
    profile["utility"] = utility

    profile["current_state_obj"] = CognitiveState(
        confidence=confidence,
        self_doubt=self_doubt,
        confusion=confusion,
        frustration=frustration,
        surprise=surprise,
        suspicion=suspicion,
        utility=utility,
    )

def export_cognitive_state(profile, attacker_name="attacker", out_dir="logs/cognitive_states"):
    """
    Exports current cognitive state to a JSON file.
    """
    state_obj = profile.get("current_state_obj", None)
    if not state_obj:
        return

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    out_path = Path(out_dir) / f"{attacker_name}_state.json"
    with open(out_path, "w") as f:
        json.dump(asdict(state_obj), f, indent=2)

def append_ctq_csv(attacker_profile, attacker_name="attacker", phase="", out_dir="logs/ctq_logs"):
    """
    Appends the attacker's psychological state to a CTQ-style CSV.
    Each row represents one MITRE phase interaction.
    """
    state = attacker_profile.get("current_state_obj", None)
    if not state:
        return

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    csv_path = Path(out_dir) / f"{attacker_name}_ctq.csv"

    file_exists = csv_path.exists()
    with open(csv_path, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "attacker", "phase", "confidence", "self_doubt",
                "confusion", "frustration", "surprise", "suspicion", "utility"
            ])
        writer.writerow([
            attacker_name, phase,
            state.confidence, state.self_doubt,
            state.confusion, state.frustration,
            state.surprise, state.suspicion, state.utility
        ])


