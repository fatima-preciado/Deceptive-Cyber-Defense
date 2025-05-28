# core/memory_graph.py
# Tracks attacker memory of tool success/failure by phase

def update_memory_graph(attacker, phase, tool, success):
    memory = attacker.setdefault("memory_graph", {})
    phase_memory = memory.setdefault(phase, {})

    if tool not in phase_memory:
        phase_memory[tool] = {
            "used": 0,
            "success": 0,
            "failure": 0
        }

    phase_memory[tool]["used"] += 1
    if success:
        phase_memory[tool]["success"] += 1
    else:
        phase_memory[tool]["failure"] += 1

