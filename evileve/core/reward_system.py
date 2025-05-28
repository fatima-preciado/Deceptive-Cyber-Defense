# core/reward_system.py

from core.psychology import update_suspicion_and_utility

def update_profile_feedback(profile, result, tool):
    psych = profile["current_psychology"]

    # Initialize Likert-scale defaults
    for k in ["confidence", "frustration", "self_doubt", "confusion", "surprise"]:
        psych[k] = psych.get(k, 2.5)

    success = result.get("success", False)
    deception = result.get("deception_triggered", False)

    profile.setdefault("tools_used", [])
    profile.setdefault("failed_attempts", {})
    profile.setdefault("success_streaks", {})

    if success:
        # 🔁 Success Streak Boosts
        streak = profile["success_streaks"].get(tool, 0) + 1
        profile["success_streaks"][tool] = streak

        confidence_gain = 0.5 + min(0.1 * streak, 0.4)      # max +0.9
        frustration_drop = 0.3 + min(0.05 * streak, 0.2)    # max -0.5
        self_doubt_drop = 0.2 + min(0.05 * streak, 0.2)     # max -0.4

        psych["confidence"] = min(5.0, psych["confidence"] + confidence_gain)
        psych["frustration"] = max(0.0, psych["frustration"] - frustration_drop)
        psych["self_doubt"] = max(0.0, psych["self_doubt"] - self_doubt_drop)
        psych["surprise"] = max(0.0, psych["surprise"] - 0.2)

        profile["tools_used"].append(tool)

    else:
        # ❌ Penalize failure
        psych["confidence"] = max(0.0, psych["confidence"] - 0.4)
        psych["frustration"] = min(5.0, psych["frustration"] + 0.6)
        psych["self_doubt"] = min(5.0, psych["self_doubt"] + 0.4)
        psych["surprise"] = min(5.0, psych["surprise"] + 0.3)

        profile["failed_attempts"].setdefault(tool, 0)
        profile["failed_attempts"][tool] += 1
        profile["success_streaks"][tool] = 0  # reset streak

        if deception:
            psych["confusion"] = min(5.0, psych["confusion"] + 0.5)
            psych["surprise"] = min(5.0, psych["surprise"] + 0.6)

    # 🧠 Additional shaping: cumulative time wasted increases pressure
    wasted = profile.get("metrics", {}).get("time_wasted", 0)
    if wasted > 30:
        psych["frustration"] = min(5.0, psych["frustration"] + 0.2)
        psych["confidence"] = max(0.0, psych["confidence"] - 0.1)

    # Recalculate suspicion and utility
    update_suspicion_and_utility(profile)

