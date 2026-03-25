import os
import re

class DependencyMapper:
    def __init__(self, base_path):
        self.base_path = base_path

    def extract_imports(self, code):
        # Find all import statements in Solidity code
        pattern = r'import\s+(?:"(.*?)"|\'(.*?)\')'
        matches = re.findall(pattern, code)
        return [match[0] or match[1] for match in matches]

    def resolve_import_paths(self, import_paths):
        resolved_paths = []
        for path in import_paths:
            full_path = os.path.join(self.base_path, path)
            if os.path.exists(full_path):
                resolved_paths.append(full_path)
            else:
                resolved_paths.append(None)  # or raise an error
        return resolved_paths
