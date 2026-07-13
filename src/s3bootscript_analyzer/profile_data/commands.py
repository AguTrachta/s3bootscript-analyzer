"""Command execution utilities for data provider pipeline stages."""

import logging
import subprocess  # nosec B404
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CommandSpec:
    """Specification for a command to be executed.

    Attributes:
        argv: Command arguments sequence.
        cwd: Working directory for command execution.
        sudo: Whether to run command with sudo privileges.
        capture_output: Whether to capture command output.
        quiet: Whether to suppress command stdout.
    """

    argv: Sequence[str]
    cwd: Path | None = None
    sudo: bool = False
    capture_output: bool = False
    quiet: bool = False
    allowed_return_codes: tuple[int, ...] = (0,)


class SubprocessRunner:
    """Simple command executor for pipeline stages.

    Stages describe what to run via CommandSpec, and this class handles
    the actual execution with proper logging and error handling.
    """

    def run(self, spec: CommandSpec) -> subprocess.CompletedProcess[bytes]:
        """Execute a command described by the given CommandSpec.

        Args:
            spec: The specification of the command to run.

        Returns:
            The result of the executed command.

        Raises:
            subprocess.CalledProcessError: If the command fails.
        """
        argv = _command_argv(spec)
        logger.info("Running: %s", " ".join(argv))
        result = _run_process(spec, argv)
        _raise_for_unexpected_return_code(spec, argv, result)
        return result


def _command_argv(spec: CommandSpec) -> list[str]:
    argv = list(spec.argv)
    if _needs_sudo_prefix(spec, argv):
        return ["sudo", *argv]
    return argv


def _needs_sudo_prefix(spec: CommandSpec, argv: list[str]) -> bool:
    return spec.sudo and (not argv or argv[0] != "sudo")


def _run_process(
    spec: CommandSpec,
    argv: list[str],
) -> subprocess.CompletedProcess[bytes]:
    if spec.capture_output:
        return subprocess.run(  # nosec B603
            argv,
            cwd=_cwd_text(spec),
            check=False,
            capture_output=True,
        )
    return subprocess.run(  # nosec B603
        argv,
        cwd=_cwd_text(spec),
        check=False,
        stdout=_stdout_target(spec),
    )


def _cwd_text(spec: CommandSpec) -> str | None:
    if spec.cwd is None:
        return None
    return str(spec.cwd)


def _stdout_target(spec: CommandSpec) -> int | None:
    if spec.quiet:
        return subprocess.DEVNULL
    return None


def _raise_for_unexpected_return_code(
    spec: CommandSpec,
    argv: list[str],
    result: subprocess.CompletedProcess[bytes],
) -> None:
    if result.returncode in spec.allowed_return_codes:
        return
    raise subprocess.CalledProcessError(
        result.returncode, argv, output=result.stdout, stderr=result.stderr
    )
