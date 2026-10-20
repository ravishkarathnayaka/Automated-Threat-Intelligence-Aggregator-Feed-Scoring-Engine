"""Unit tests for multi-tenant risk tolerance profiles."""

from cti_core.scoring.tenant_profiles import TenantProfileManager


def test_tenant_profile_retrieval():
    zt = TenantProfileManager.get_profile("zero_trust")
    assert zt.min_enforcement_score == 85.0
    assert zt.required_consensus == 3
    assert zt.quarantine_unconfirmed is True

    ent = TenantProfileManager.get_profile("enterprise_standard")
    assert ent.min_enforcement_score == 70.0
    assert ent.required_consensus == 2

    hunt = TenantProfileManager.get_profile("threat_hunting")
    assert hunt.min_enforcement_score == 40.0
    assert hunt.required_consensus == 1
    assert hunt.quarantine_unconfirmed is False


def test_tenant_profile_fallback():
    fb = TenantProfileManager.get_profile("non_existent_profile")
    assert fb.name == "enterprise_standard"
