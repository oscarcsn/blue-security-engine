"""Verify demo reporting follows the actual authentication result."""
import contextlib
import io
import unittest
from unittest.mock import patch

import demo
from bse import demo as packaged_demo


class TestDemo(unittest.TestCase):
    def test_source_entrypoint_shares_the_packaged_implementation(self):
        self.assertIs(demo.run_demo, packaged_demo.run_demo)
        self.assertIs(demo.EvidenceManifest, packaged_demo.EvidenceManifest)

    def test_console_entrypoint_returns_failure_for_failed_demo(self):
        with patch.object(packaged_demo, "run_demo", return_value=False):
            self.assertEqual(packaged_demo.main(), 1)
        with patch.object(packaged_demo, "run_demo", return_value=True):
            self.assertEqual(packaged_demo.main(), 0)

    def test_demo_reports_success_after_real_hmac_verification(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(demo.run_demo())
        self.assertIn("DEMO CHECKS PASSED", output.getvalue())
        self.assertIn("HMAC=OK", output.getvalue())

    def test_demo_does_not_claim_success_when_authentication_fails(self):
        failed = {"valid": False, "artifacts": {}, "hmac": {"valid": False, "status": "HASH_MISMATCH"}}
        with patch.object(demo.EvidenceManifest, "verify_manifest", return_value=failed):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertFalse(demo.run_demo())
        self.assertIn("DEMO CHECKS FAILED", output.getvalue())
        self.assertNotIn("DEMO CHECKS PASSED", output.getvalue())
        self.assertIn("Authentication: FAIL", output.getvalue())


if __name__ == "__main__":
    unittest.main()
