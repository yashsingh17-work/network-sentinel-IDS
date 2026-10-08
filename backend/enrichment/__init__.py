"""Optional, privacy-conscious IP context enrichment."""

from backend.enrichment.ip_context import IpContext, IpEnrichmentService
from backend.enrichment.ports import PortInfo, describe_port

__all__ = ["IpContext", "IpEnrichmentService", "PortInfo", "describe_port"]
