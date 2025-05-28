# core/monitor_tools.py

import os
import signal
import time

def is_running(pid):
    """Check if a process is currently alive."""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def poll_process(pid):
    """Return exit code if finished, None if still running."""
    try:
        _, status = os.waitpid(pid, os.WNOHANG)
        if status == 0:
            return None
        return os.WEXITSTATUS(status)
    except ChildProcessError:
        return None
    except Exception as e:
        print(f"[monitor] poll_process error: {e}")
        return None

def kill_process_group(pid, grace=3):
    """
    Try to SIGTERM the process group, then SIGKILL if needed.
    """
    try:
        os.killpg(pid, signal.SIGTERM)
        print(f"[monitor] Sent SIGTERM to PID group {pid}")
        time.sleep(grace)
        if is_running(pid):
            os.killpg(pid, signal.SIGKILL)
            print(f"[monitor] Sent SIGKILL to PID group {pid}")
        return True
    except Exception as e:
        print(f"[monitor] Failed to kill PID group {pid}: {e}")
        return False

def monitor_active_tools(active_tools, timeout=60):
    """
    Checks if tools in the active list are still running or have finished.
    If timeout is exceeded, the process group is terminated.
    Returns a list of completed or killed entries.
    """
    now = time.time()
    completed = []

    for entry in list(active_tools):  # safe copy
        pid = entry.get("pid")
        tool = entry.get("tool", "unknown")
        start = entry.get("start_time", now)
        elapsed = now - start

        if not pid or not isinstance(pid, int):
            print(f"[monitor] Invalid PID entry: {pid}")
            entry["status"] = "invalid"
            entry["exit_code"] = None
            active_tools.remove(entry)
            completed.append(entry)
            continue

        # Process finished
        if not is_running(pid):
            exit_code = poll_process(pid)
            print(f"[monitor] {tool} (pid={pid}) finished. Exit code: {exit_code}")
            entry["status"] = "finished"
            entry["exit_code"] = exit_code
            active_tools.remove(entry)
            completed.append(entry)

        # Timeout exceeded
        elif elapsed > timeout:
            print(f"[monitor] Timeout: {tool} (pid={pid}) exceeded {timeout}s. Killing...")
            kill_process_group(pid)
            entry["status"] = "timeout"
            entry["exit_code"] = None
            active_tools.remove(entry)
            completed.append(entry)

        else:
            print(f"[monitor] {tool} (pid={pid}) running... {elapsed:.1f}s")

    return completed


