import re as _re

from seeyoucm_thief._version import __version__ as _raw_version
from seeyoucm_thief._version import __version_tuple__

# Clean setuptools-scm version for display:
#   "0.1.1.dev3+gabcdef1.d20260227" -> "0.1.1"
#   "0.1.0" -> "0.1.0"
__version__ = _re.sub(r"(\.dev\d+|\+g[a-f0-9]+|\.d\d{8})", "", _raw_version)

__all__ = ["__version__", "__version_tuple__"]
