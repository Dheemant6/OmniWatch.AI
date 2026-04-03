import logging
import tempfile
from app.worker.celery_app import celery_app
from app.services.ingestion.git_manager import GitIngestionManager
from app.services.analyzer.semantic_ai import SemanticAIScanner
from app.services.sbom.generator import SBOMGenerator

logger = logging.getLogger(__name__)

@celery_app.task(bind=True)
def run_security_scan(self, repo_url: str, repo_name: str):
    """
    Orchestrates the entire security scan pipeline for a repository.
    Called asynchronously by the webhook receiver.
    """
    logger.info(f"Starting async security scan for {repo_url}")
    
    # 1. Create temporary workspace
    with tempfile.TemporaryDirectory() as temp_dir:
        
        # 2. Ingest
        git_manager = GitIngestionManager()
        success = git_manager.clone_repository(repo_url, temp_dir)
        if not success:
            logger.error("Scan aborted due to cloning failure.")
            return

        git_manager.sanitize_workspace(temp_dir)
        
        # 3. SBOM Generation
        sbom_gen = SBOMGenerator()
        sbom_data = sbom_gen.build_sbom(temp_dir, repo_name)
        
        # 4. Semantic AI Analysis
        scanner = SemanticAIScanner()
        vulns = scanner.analyze_workspace(temp_dir)
        
        logger.info(f"Scan complete. Found {len(vulns)} vulnerabilities.")
        
        # 5. Database updates and webhooks would occur here
        
    return True
