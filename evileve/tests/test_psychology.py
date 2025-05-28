# tests/test_psychology.py

import pytest
from core import psychology

def make_profile(confidence=2.5, self_doubt=2.5, confusion=2.5, frustration=2.5, surprise=2.5, perceived_risk=2.5):
    return {
        "current_psychology": {
            "confidence": confidence,
            "self_doubt": self_doubt,
            "confusion": confusion,
            "frustration": frustration,
            "surprise": surprise
        },
        "perceived_risk": perceived_risk
    }

def test_correlation_increases_confusion_and_surprise():
    profile = make_profile(frustration=4.0)
    psychology.apply_correlations(profile)
    traits = profile["current_psychology"]
    assert traits["confusion"] > 2.5
    assert traits["surprise"] > 2.5

def test_correlation_decreases_confidence():
    profile = make_profile(self_doubt=4.0)
    psychology.apply_correlations(profile)
    traits = profile["current_psychology"]
    assert traits["confidence"] < 2.5

def test_suspicion_calculation_midrange():
    profile = make_profile(confidence=3.0, self_doubt=3.0, confusion=3.0, frustration=3.0)
    psychology.update_suspicion_and_utility(profile)
    assert 2.0 <= profile["suspicion"] <= 5.0

def test_utility_clamping():
    profile = make_profile(confidence=5.0, perceived_risk=5.0)
    psychology.update_suspicion_and_utility(profile)
    assert profile["utility"] == 0.0

def test_trait_bounds_respected():
    profile = make_profile(confidence=10.0, self_doubt=-5.0)
    psychology.apply_correlations(profile)
    traits = profile["current_psychology"]
    assert 0.0 <= traits["confidence"] <= 5.0
    assert 0.0 <= traits["surprise"] <= 5.0
    assert 0.0 <= traits["confusion"] <= 5.0
