"""Check the typing resource through the public installed-package resource API."""
from importlib import resources
import unittest


class TestPackageResources(unittest.TestCase):
    def test_pep561_marker_is_available_as_a_package_resource(self):
        marker = resources.files("bse").joinpath("py.typed")
        self.assertTrue(marker.is_file(), "Installed BSE must expose its PEP 561 marker")
        with marker.open("rb") as stream:
            self.assertIsInstance(stream.read(), bytes)


if __name__ == "__main__":
    unittest.main()
