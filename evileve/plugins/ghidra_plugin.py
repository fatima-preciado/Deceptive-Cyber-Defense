# plugins/ghidra_plugin.py

import os
import subprocess
from pathlib import Path
from plugins.utils.errors import safe_open

class GhidraHeadlessPlugin:
    """
    Wrapper for launching Ghidra's analyzeHeadless in a background subprocess.
    """

    def __init__(self, ghidra_path, binary_path, project_path, log_path):
        """
        Initializes the plugin with paths and target.

        Args:
            ghidra_path (str): Path to Ghidra installation.
            binary_path (str): Path to binary to analyze.
            project_path (str): Project directory for headless analysis.
            log_path (str): Where to log analysis output.
        """
        self.ghidra_path = ghidra_path
        self.binary_path = binary_path
        self.project_path = project_path
        self.log_path = log_path

    def run(self):
        """
        Executes the Ghidra headless analysis in background with nohup.
        """
        Path(self.project_path).mkdir(parents=True, exist_ok=True)

        cmd = [
            "nohup",
            "./support/analyzeHeadless",
            self.project_path, "evileve_proj",
            "-import", self.binary_path,
            "-deleteProject"
        ]

        try:
            with safe_open(self.log_path, "w") as logfile:
                subprocess.Popen(
                    cmd,
                    cwd=self.ghidra_path,
                    stdout=logfile,
                    stderr=subprocess.STDOUT,
                    preexec_fn=os.setpgrp  # Run detached
                )
            print(f"[ghidra_plugin] Launched headless Ghidra for {self.binary_path}")
        except Exception as e:
            print(f"[ghidra_plugin] Failed to launch Ghidra: {e}")
            raise
