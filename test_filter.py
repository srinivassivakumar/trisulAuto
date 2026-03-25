#!/usr/bin/env python3
import sys
sys.path.insert(0, r'C:\sri\trisulauto')

from importlib.util import spec_from_file_location, module_from_spec

# Import 11thsteptest dynamically
spec = spec_from_file_location("step11", r"C:\sri\trisulauto\11thsteptest.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)

# Run in console mode (output_file=None)
try:
    infra = module.load_infra_snapshot(
        r'C:\sri\trisulauto\vm_data.json',
        r'C:\sri\trisulauto\ram_resources.json',
        r'C:\sri\trisulauto\CPU_resources.json'
    )
    module.fetch_tcp_analyzer_counters('SYS:CGI', output_file=None, infra_snapshot=infra)
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
