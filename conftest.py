import importlib.util
import sys
from pathlib import Path
root = Path(__file__).parent
spec = importlib.util.spec_from_file_location('astrbot_plugin_cve_card', root / '__init__.py', submodule_search_locations=[str(root)])
module = importlib.util.module_from_spec(spec)
sys.modules['astrbot_plugin_cve_card'] = module
spec.loader.exec_module(module)
