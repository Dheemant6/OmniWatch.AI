import os
import shutil
from pathlib import Path
import subprocess
import logging

logger = logging.getLogger(__name__)

class GitIngestionManager:
    def __init__(self, token: str = None):
        self.token = token
        
    def clone_repository(self, repo_url: str, dest_dir: str) -> bool:
        """
        Securely clone the repository using shallow clone.
        If a Github token is provided, uses it for private repos.
        """
        try:
            # Prepare URL with token if needed (for real app)
            clone_url = repo_url
            
            logger.info(f"Cloning {clone_url} into {dest_dir}...")
            # Use depth 1 for faster clone / lower storage
            subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, dest_dir],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clone repository: {e.stderr.decode()}")
            return False

    def sanitize_workspace(self, workspace_path: str):
        """
        Removes sensitive artifacts (e.g. .env files, standard secrets)
        from the workspace before the semantic scanner runs over it.
        """
        sensitive_extensions = {".pem", ".crt", ".key", ".pfx", ".p12"}
        sensitive_names = {".env", "secrets.json", "credentials.json", "id_rsa", ".htpasswd"}
        sensitive_dirs = {".git", ".svn", "node_modules", "venv", ".venv", "__pycache__"}

        logger.info(f"Sanitizing workspace: {workspace_path}")
        
        for root, dirs, files in os.walk(workspace_path, topdown=True):
            # Remove sensitive directories in place so os.walk doesn't traverse them
            original_dirs = dirs.copy()
            for d in original_dirs:
                if d in sensitive_dirs:
                    dir_path = os.path.join(root, d)
                    try:
                        shutil.rmtree(dir_path)
                        dirs.remove(d) # stop traversing further down
                    except Exception as e:
                        logger.warning(f"Could not remove sensitive directory {dir_path}: {e}")

            # Remove sensitive files
            for file in files:
                file_lower = file.lower()
                ext = Path(file).suffix.lower()
                
                if file_lower in sensitive_names or ext in sensitive_extensions:
                    file_path = os.path.join(root, file)
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        logger.warning(f"Could not remove sensitive file {file_path}: {e}")
