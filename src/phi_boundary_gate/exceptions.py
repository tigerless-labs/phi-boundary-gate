"""Stable package exceptions for callers that need typed error handling."""

from __future__ import annotations


class PhiBoundaryGateError(ValueError):
    """Base class for package-level validation and integration errors."""


class PolicyError(PhiBoundaryGateError):
    """Raised when a PHI policy cannot be loaded or validated."""


class ProjectConfigError(PhiBoundaryGateError):
    """Raised when project discovery or config validation fails."""


class ProjectConfigNotFoundError(ProjectConfigError, FileNotFoundError):
    """Raised when project config discovery cannot find a config file."""


class TraceMappingError(PhiBoundaryGateError):
    """Raised when an external trace mapping or conversion fails."""
