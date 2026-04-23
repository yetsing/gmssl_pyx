import os
import sys
import unittest


def main():
    loader = unittest.defaultTestLoader
    repeat = int(os.environ.get("TEST_REPEAT", "1"))
    for _ in range(repeat):
        suite = loader.discover("tests")
        runner = unittest.TextTestRunner(verbosity=1)
        result = runner.run(suite)
        # If there were any failures or errors, exit 1
        if not result.wasSuccessful():
            sys.exit(1)


if __name__ == "__main__":
    main()
