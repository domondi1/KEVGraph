"""Ecosystem adapters for KEVGraph."""

from .maven import MavenAdapter
from .npm import NpmAdapter
from .pypi import PyPIAdapter

__all__ = ["NpmAdapter", "PyPIAdapter", "MavenAdapter"]
