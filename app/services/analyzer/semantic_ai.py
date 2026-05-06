import os
import json
import logging
from openai import OpenAI
from app.core.config import settings

logger = logging.getLogger(__name__)

class SemanticAIScanner:
    def __init__(self, model_name: str = "qwen2.5-coder:7b"):
        self.model_name = model_name
        self.client = OpenAI(
            base_url=settings.OPENAI_API_BASE,
            api_key=settings.OPENAI_API_KEY
        )

    def analyze_workspace(self, workspace_path: str) -> list:
        """
        Scans all text/code files in the workspace using the local Ollama server.
        Returns a list of discovered vulnerabilities.
        """
        logger.info(f"Initiating semantic analysis on {workspace_path} with model {self.model_name}")
        vulnerabilities = []
        
        system_prompt = (
            "You are an expert AI security scanner. Analyze the following code snippet for vulnerabilities. "
            "Correlate your findings against known threat lists like OWASP Top 10. "
            "If you find an issue, return a JSON array of objects with keys: "
            "'severity', 'title', 'description', 'file', 'line', 'cwe_reference', 'vulnerable_code', 'remediation', 'remediation_patch'. "
            "The 'cwe_reference' MUST be a string like 'CWE-89' or 'OWASP-A1'. "
            "The 'vulnerable_code' MUST contain the exact original lines that are vulnerable. "
            "The 'remediation_patch' MUST contain the secure drop-in replacement lines. "
            "If no vulnerabilities are found, return an empty JSON array '[]'. "
            "Respond ONLY with valid JSON."
        )
        
        from app.services.vector.pinecone_manager import PineconeManager
        vector_db = PineconeManager()

        # Traverse the workspace finding code files
        for root, dirs, files in os.walk(workspace_path):
            # Skip hidden dirs like .git
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if file.startswith('.'):
                    continue
                    
                filepath = os.path.join(root, file)
                
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        code_content = f.read()
                        
                    # Skip extremely large files for now (to avoid immediate context window overflow)
                    if len(code_content) > 100000:
                        logger.warning(f"Skipping {filepath} - file too large.")
                        continue
                        
                    # AST augmentation for python files
                    ast_context = ""
                    if file.endswith('.py'):
                        from app.services.analyzer.ast_extractor import ASTExtractor
                        ast_ext = ASTExtractor()
                        ast_data = ast_ext.extract_from_file(filepath)
                        ast_context = "\n" + ast_ext.format_for_llm(ast_data)
                        
                    # RAG Augmentation (fetch previous similar vulnerabilities)
                    rag_context_str = ""
                    similar_vulns = vector_db.search_similar(code_content[:1000], top_k=3)
                    if similar_vulns:
                        historical = "\n".join([str(v) for v in similar_vulns])
                        rag_context_str = f"\n\n[Historical RAG Context - Similar Past Vulnerabilities]:\n{historical}"
                        
                    final_content = f"File: {file}\n{ast_context}{rag_context_str}\nCode:\n{code_content}"
                        
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": final_content}
                        ],
                        temperature=0.1
                    )
                    
                    output_text = response.choices[0].message.content
                    
                    try:
                        # Sometimes models wrap json in markdown
                        clean_json = output_text.strip().removeprefix("```json").removesuffix("```").strip()
                        findings = json.loads(clean_json)
                        if isinstance(findings, list):
                            for finding in findings:
                                finding['file'] = file # ensure file context is kept
                                
                                orig = finding.get('vulnerable_code', '')
                                patch = finding.get('remediation_patch', '')
                                
                                if not orig and finding.get('line'):
                                    try:
                                        line_num = int(finding.get('line'))
                                        lines = code_content.split('\n')
                                        if 0 < line_num <= len(lines):
                                            orig = lines[line_num - 1].strip()
                                    except Exception:
                                        pass
                                
                                if patch and not str(patch).strip().startswith('-'):
                                    diff_str = ""
                                    if orig:
                                        for line in str(orig).split('\n'):
                                            if line.strip(): diff_str += f"- {line}\n"
                                    else:
                                        diff_str += "- # Vulnerable code\n"
                                        
                                    for line in str(patch).split('\n'):
                                        if line.strip(): diff_str += f"+ {line}\n"
                                    finding['remediation_patch'] = diff_str.strip()
                                    
                                vulnerabilities.append(finding)
                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse JSON from AI response on file {file}: {output_text}")
                        
                except UnicodeDecodeError:
                    # Skip binary files
                    pass
                except Exception as e:
                    logger.error(f"Error scanning {filepath}: {str(e)}")
                    
        return vulnerabilities
