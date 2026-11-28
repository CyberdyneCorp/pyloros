"""Both frontend gates must finish if the local engine stalls during image lookup."""
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_frontend_image
import check_frontend_start


class FrontendImageLookup(unittest.TestCase):
    def test_stalled_engine_fails_before_container_creation(self):
        def stalled(command, **kwargs):
            self.assertEqual(command, ["docker", "image", "inspect", "--format", "{{.Id}}", "console"])
            self.assertEqual(kwargs.get("timeout"), 10)
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        checks = [check_frontend_start.check, lambda image: check_frontend_image.inspect(image, True)]
        for check in checks:
            with self.subTest(check=check), patch("subprocess.check_output", side_effect=stalled) as cli:
                with self.assertRaisesRegex(ValueError, "Docker image lookup timed out"):
                    check("console")
                cli.assert_called_once()


if __name__ == "__main__":
    unittest.main()
