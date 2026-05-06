import ast
import logging

logger = logging.getLogger(__name__)

class ASTExtractor:
    """
    Extracts structural metadata (Abstract Syntax Tree) from Python files
    to provide enhanced context to the Semantic AI engine.
    """
    
    def extract_from_file(self, filepath: str) -> dict:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                code = f.read()
            tree = ast.parse(code)
            
            data = {"classes": [], "functions": [], "imports": []}
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    data["classes"].append({
                        "name": node.name,
                        "line": node.lineno
                    })
                elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                    data["functions"].append({
                        "name": node.name,
                        "line": node.lineno
                    })
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        data["imports"].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        data["imports"].append(node.module)
            return data
        except Exception as e:
            logger.error(f"AST extraction failed for {filepath}: {e}")
            return {"classes": [], "functions": [], "imports": []}

    def format_for_llm(self, ast_data: dict) -> str:
        if not ast_data.get("classes") and not ast_data.get("functions") and not ast_data.get("imports"):
            return ""
        
        context = "[AST Context]:\n"
        if ast_data.get("imports"):
            context += "Imports: " + ", ".join(list(set(ast_data["imports"]))) + "\n"
        if ast_data.get("classes"):
            context += "Classes defined: " + ", ".join([f"{c['name']} (line {c['line']})" for c in ast_data["classes"]]) + "\n"
        if ast_data.get("functions"):
            context += "Functions defined: " + ", ".join([f"{f['name']} (line {f['line']})" for f in ast_data["functions"]]) + "\n"
            
        return context
