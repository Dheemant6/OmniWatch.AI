from github import Github
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

class PRRemediationManager:
    def __init__(self):
        self.token = settings.GITHUB_TOKEN
        self.client = Github(self.token) if self.token else None

    def post_vulnerabilities_to_pr(self, repo_url: str, pr_number: int, vulnerabilities: list):
        """
        Takes a list of standard vulnerabilities dicts and posts them to the PR.
        If no token is provided, it simply logs them (useful for local dev).
        """
        try:
            repo_path = repo_url.rstrip('/').split('/')[-2:]
            repo_full_name = f"{repo_path[0]}/{repo_path[1]}"
        except Exception:
            logger.error(f"Could not parse repo path from {repo_url}")
            return
            
        if not self.client:
            logger.info(f"No GITHUB_TOKEN configured. Mocking PR comment for {repo_full_name} PR #{pr_number}")
            for v in vulnerabilities:
                logger.info(f"[MOCK PR COMMENT] File: {v.get('file')} | Issue: {v.get('title')}\nPatch: {v.get('remediation_patch')}")
            return

        try:
            repo = self.client.get_repo(repo_full_name)
            pull = repo.get_pull(pr_number)
            
            commits = list(pull.get_commits())
            commit = commits[-1] if commits else None
            
            general_vulns = []
            
            for v in vulnerabilities:
                patch = v.get("remediation_patch")
                file_path = v.get("file")
                line_obj = v.get("line")
                
                # Check if we can post an inline review comment
                if patch and file_path and line_obj and str(line_obj).isdigit() and commit:
                    line = int(line_obj)
                    body = f"**OmniWatch Security Issue**: {v.get('title')} ({v.get('severity', 'moderate').upper()})\n"
                    body += f"{v.get('description')}\n\n"
                    body += f"```suggestion\n{patch}\n```\n"

                    try:
                        pull.create_review_comment(
                            body=body,
                            commit=commit,
                            path=file_path,
                            line=line
                        )
                        continue  # Success
                    except Exception as e:
                        logger.warning(f"Could not post review comment for {file_path}:{line}. Fallback to generic comment. Error: {e}")
                
                general_vulns.append(v)
            
            # Fallback to general comments
            issue = repo.get_issue(number=pr_number)
            
            body = "## OmniWatch AI Security Scan Results\n\n"
            if len(general_vulns) == 0 and len(vulnerabilities) > 0:
                body += "✅ Contextual security patches have been left as inline PR review comments."
            elif len(vulnerabilities) == 0:
                body += "✅ No vulnerabilities detected."
            else:
                body += f"⚠️ **{len(general_vulns)} vulnerabilities logged.** (Inline patches may also exist above)\n\n"
                for v in general_vulns:
                    body += f"### {v.get('title')} ({v.get('severity', 'moderate').upper()})\n"
                    body += f"**File**: `{v.get('file')}`\n"
                    body += f"**Description**: {v.get('description')}\n"
                    
                    patch_content = v.get('remediation_patch') or v.get('remediation')
                    if patch_content:
                        body += f"**Suggested Remediation**:\n```\n{patch_content}\n```\n"
                    body += "---\n"
                    
            if len(general_vulns) > 0 or len(vulnerabilities) == 0:
                issue.create_comment(body)
                
            logger.info(f"Successfully processed scan results for {repo_full_name} PR #{pr_number}")
        except Exception as e:
            logger.error(f"Failed to post to GitHub: {e}")
