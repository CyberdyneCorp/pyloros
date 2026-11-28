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


class FrontendStartupDeadline(unittest.TestCase):
    def test_probe_gets_only_the_time_left_after_start_and_inspect(self):
        now = 0

        def engine(command, *args, **kwargs):
            nonlocal now
            if command == "create":
                return "test-container"
            if command == "start":
                self.assertEqual(kwargs["timeout"], 30)
                now += 17
            elif command == "inspect":
                self.assertEqual(kwargs["timeout"], 13)
                now += 8
                return "true"
            elif command == "rm":
                self.assertEqual(args, ("--force", "-v", "test-container"))
                self.assertEqual(kwargs["timeout"], 10)
            else:
                self.fail(f"unexpected Docker command {command}")

        def stalled_probe(command, **kwargs):
            self.assertEqual(kwargs["timeout"], 5)
            raise subprocess.TimeoutExpired(command, 5)

        with (
            patch.object(check_frontend_start, "local_image_id", return_value="test-image"),
            patch.object(check_frontend_start, "monotonic", side_effect=lambda: now),
            patch.object(check_frontend_start, "docker", side_effect=engine) as docker,
            patch.object(check_frontend_start.subprocess, "run", side_effect=stalled_probe),
        ):
            with self.assertRaisesRegex(ValueError, "within 30 seconds"):
                check_frontend_start.check("console")
            self.assertEqual([call.args[0] for call in docker.call_args_list],
                             ["create", "start", "inspect", "rm"])


if __name__ == "__main__":
    unittest.main()
