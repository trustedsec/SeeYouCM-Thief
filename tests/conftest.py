#!/usr/bin/env python3
"""
Pytest configuration file to enable importing thief module
"""
import sys
from pathlib import Path

# Add the parent directory to sys.path so we can import thief
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))
