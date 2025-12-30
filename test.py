import unittest
import sys

def main():
    loader = unittest.defaultTestLoader
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    # If there were any failures or errors, exit 1
    if not result.wasSuccessful():
        sys.exit(1)

if __name__ == "__main__":
    main()
