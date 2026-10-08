from backend.config import Settings
from backend.enrichment import IpEnrichmentService


def test_labels_private_addresses_without_external_lookup() -> None:
    service = IpEnrichmentService(Settings(reverse_dns_enabled=False, country_lookup_enabled=False))

    context = service.describe("192.168.1.25")

    assert context.status == "ready"
    assert context.label == "192.168.1.25 (Private or local network)"


def test_marks_public_context_disabled_without_any_lookup() -> None:
    service = IpEnrichmentService(Settings(reverse_dns_enabled=False, country_lookup_enabled=False))

    context = service.describe("8.8.8.8")

    assert context.label == "8.8.8.8"
    assert context.status == "disabled"
