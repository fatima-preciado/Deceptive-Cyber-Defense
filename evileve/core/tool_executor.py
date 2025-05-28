# core/tool_executor.py

from subprocess import Popen, DEVNULL
import os
import time

def execute_tool(tool, args, dry_run=False):
    if dry_run:
        print(f"[dry-run] Simulating tool execution: {tool} {' '.join(args)}")
        return {
            "tool": tool,
            "args": args,
            "pid": 99999,  # dummy PID
            "launched": False,
            "runtime": 0.01,
            "success": None,
            "exit_code": None,
            "stderr": "[dry-run] Execution skipped.",
            "deception_triggered": False
        }

    try:
        start = time.time()
        process = Popen(
            [tool] + args,
            stdout=DEVNULL, stderr=DEVNULL,
            preexec_fn=os.setpgrp
        )
        end = time.time()

        return {
            "tool": tool,
            "args": args,
            "pid": process.pid,
            "launched": True,
            "runtime": round(end - start, 3),
            "success": None,
            "exit_code": None,
            "deception_triggered": False
        }

    except Exception as e:
        return {
            "tool": tool,
            "args": args,
            "pid": None,
            "launched": False,
            "runtime": 0.0,
            "success": False,
            "exit_code": -1,
            "stderr": str(e),
            "deception_triggered": False
        }


