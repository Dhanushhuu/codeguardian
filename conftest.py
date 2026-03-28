# """
# conftest.py
# Adds the project root to sys.path so that all imports like
# `from tools.xxx import yyy` and `from graph.xxx import yyy`
# work correctly when running tests from any directory.

# Place this file in the project ROOT (same level as requirements.txt).
# """

import sys
import os

# Insert project root at the front of sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))