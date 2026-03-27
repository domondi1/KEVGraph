"""Ecosystem adapters for KEVGraph."""

from .npm import NpmAdapter
from .pypi import PyPIAdapter

__all__ = ["NpmAdapter", "PyPIAdapter"]
