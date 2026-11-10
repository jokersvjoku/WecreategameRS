from abc import ABC, abstractmethod
from typing import List
from app.models_core import Vulnerability


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner name."""

    @abstractmethod
    def scan(self, code: str, filename: str) -> List[Vulnerability]:
        """
        Analyze code and return a list of detected vulnerabilities.
        IMPORTANT: Must never execute the provided code.
        """
