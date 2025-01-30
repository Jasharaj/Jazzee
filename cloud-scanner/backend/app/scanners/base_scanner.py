from abc import ABC, abstractmethod
from typing import List, Dict
from ..models.scan_result import Finding, ResourceConfig

class BaseScanner(ABC):
    def __init__(self, session):
        self.session = session
        self.findings: List[Finding] = []
        self.resources: List[ResourceConfig] = []

    @abstractmethod
    async def scan(self) -> List[Finding]:
        """Execute the security scan"""
        pass

    @abstractmethod
    async def get_resources(self) -> List[ResourceConfig]:
        """Get all resources of this type"""
        pass

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_resource(self, resource: ResourceConfig):
        self.resources.append(resource)
