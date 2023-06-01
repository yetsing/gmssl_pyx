import unittest

def main():
    loader = unittest.defaultTestLoader
    suite = loader.discover('tests')
    runner = unittest.TextTestRunner()
    runner.run(suite)


if __name__ == "__main__":
    main()
