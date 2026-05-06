import logging
import tempfile
import asyncio
from datetime import datetime
from app.worker.celery_app import celery_app
from app.services.ingestion.git_manager import GitIngestionManager
from app.services.analyzer.semantic_ai import SemanticAIScanner
from app.services.analyzer.supply_chain import SupplyChainAnalyzer
from app.services.sbom.generator import SBOMGenerator
from app.services.remediation.pr_manager import PRRemediationManager
from app.services.storage.s3_manager import S3Manager
from app.services.vector.pinecone_manager import PineconeManager
from app.db.session import AsyncSessionLocal
from app.db.models.scan import ScanJob, Vulnerability

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    import os
    log_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "app.log")
    file_handler = logging.FileHandler(log_file, mode='a')
    formatter = logging.Formatter("%(asctime)s.%(msecs)03dZ [%(levelname)s] Worker: %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

async def run_async_pipeline(repo_url: str, repo_name: str, task_id: str, pr_number: int = None):
    logger.info(f"Starting async security scan for {repo_url}")
    
    async def update_stage(stage_name: str, scan_db_id: int):
        logger.info(f"[PIPELINE_STAGE] [{repo_name}] {stage_name}")
        async with AsyncSessionLocal() as db:
            s = await db.get(ScanJob, scan_db_id)
            if s:
                s.current_stage = stage_name
                await db.commit()

    async with AsyncSessionLocal() as session:
        scan_job = ScanJob(repo_url=repo_url, repo_name=repo_name, status="in_progress", task_id=task_id, current_stage="Initializing Pipeline")
        session.add(scan_job)
        await session.commit()
        await session.refresh(scan_job)
        scan_id = scan_job.id

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            await update_stage("Cloning Target Repository", scan_id)
            git_manager = GitIngestionManager()
            success = git_manager.clone_repository(repo_url, temp_dir)
            if not success:
                logger.error("Scan aborted due to cloning failure.")
                await update_stage("Failed during Cloning", scan_id)
                async with AsyncSessionLocal() as session:
                    scan = await session.get(ScanJob, scan_id)
                    scan.status = "failed"
                    await session.commit()
                return
                
            git_manager.sanitize_workspace(temp_dir)
            
            await update_stage("Generating SBOM & Extracting Dependencies", scan_id)
            sbom_gen = SBOMGenerator()
            sbom_data = await sbom_gen.build_sbom(temp_dir, repo_name)
            
            s3_manager = S3Manager()
            s3_manager.upload_artifact(f"sboms/{repo_name}_{scan_id}.json", sbom_data)
            
            await update_stage("Running Supply Chain Vulnerability Scan", scan_id)
            supply_chain_analyzer = SupplyChainAnalyzer()
            supply_chain_vulns = await supply_chain_analyzer.check_vulnerabilities(sbom_data)
            
            from app.services.sbom.license_checker import check_compliance
            license_issues = check_compliance(sbom_data)
            for iss in license_issues:
                supply_chain_vulns.append({
                    "file": "manifest file",
                    "line": 0,
                    "severity": "high",
                    "title": "License Compliance Violation",
                    "description": f"Component {iss['component']} ({iss['version']}) uses banned license: {iss['license']}.",
                    "remediation": f"Remove or replace {iss['component']} to comply with policy."
                })
            
            await update_stage("Running Deep Semantic AI Analysis", scan_id)
            ai_scanner = SemanticAIScanner()
            code_vulns = ai_scanner.analyze_workspace(temp_dir)
            
            await update_stage("Syncing Vectors & Uploading Artifacts", scan_id)
            pinecone_manager = PineconeManager()
            for idx, finding in enumerate(code_vulns):
                finding_id = f"scan_{scan_id}_vuln_{idx}"
                text_context = f"{finding.get('title')}: {finding.get('description')}\n{finding.get('remediation_patch')}"
                pinecone_manager.upsert_finding(finding_id, text_context, metadata={"scan_id": scan_id, "repo": repo_name})
            
            all_vulns = supply_chain_vulns + code_vulns
            logger.info(f"[PIPELINE_STAGE] [{repo_name}] Scan complete. Found {len(all_vulns)} total vulnerabilities.")
            
            await update_stage("Finalizing Security Report", scan_id)
            async with AsyncSessionLocal() as session:
                scan = await session.get(ScanJob, scan_id)
                scan.status = "completed"
                scan.current_stage = "Completed"
                scan.completed_at = datetime.utcnow()
                scan.sbom_data = sbom_data
                
                for v in all_vulns:
                    vuln_record = Vulnerability(
                        scan_id=scan.id,
                        file_path=v.get("file", "unknown"),
                        line_number=v.get("line"),
                        severity=v.get("severity", "medium").lower(),
                        title=v.get("title", "Found Vulnerability"),
                        description=v.get("description", ""),
                        remediation_patch=v.get("remediation_patch", v.get("remediation", "")),
                        cwe_reference=v.get("cwe_reference"),
                        cve_reference=v.get("cve_reference")
                    )
                    session.add(vuln_record)
                await session.commit()

            if pr_number:
                await update_stage("Posting Auto-Remediation PR", scan_id)
                pr_manager = PRRemediationManager()
                pr_manager.post_vulnerabilities_to_pr(repo_url, pr_number, all_vulns)
        except Exception as e:
            logger.error(f"Scan failed with error: {str(e)}")
            await update_stage(f"Failed: {str(e)[:50]}...", scan_id)
            async with AsyncSessionLocal() as session:
                scan = await session.get(ScanJob, scan_id)
                scan.status = "failed"
                await session.commit()

@celery_app.task(bind=True)
def run_security_scan(self, repo_url: str, repo_name: str, pr_number: int = None):
    """
    Celery task entrypoint. Orchestrates the entire security scan pipeline natively.
    """
    task_id = self.request.id
    asyncio.run(run_async_pipeline(repo_url, repo_name, task_id, pr_number))
    return True
