#!/usr/bin/env python3
import sys
import seeyoucm_thief.thief as _mod

# Replace this module in sys.modules so that `import thief` resolves
# to the real package module. This ensures monkeypatching (e.g. in tests)
# modifies the actual module namespace.
sys.modules[__name__] = _mod

if __name__ == '__main__':
    _mod.main()
