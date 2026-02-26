"""
STRATIX SDK — Validator test suite
© 2026 Intelligent Consulting BV. All rights reserved.
"""

import pytest
from stratix.validator import (
    StratixValidator, StratixPipeline, AccessLogEntry,
    IntentCategory, KillChainPhase, DataClassification,
)


VALID_EVENT = {
    "class_uid": 4001,
    "category_uid": 4,
    "time": "2026-02-26T14:00:00+00:00",
    "metadata": {"version": "1.3.0", "product": {"name": "Test", "vendor": "Test", "version": "1.0"}},
    "intent": {
        "category": "lateral_movement",
        "technique_id": "T1021.001",
        "confidence_score": 87,
        "kill_chain_phase": "actions_on_objectives",
        "blast_radius": ["domain_controllers"],
    },
    "sovereignty": {
        "data_residency": "BE",
        "classification": "restricted",
        "nis2_category": "essential_entity",
        "eucs_assurance_level": "high",
        "dora_ict_asset": True,
    },
}


class TestOCSFBase:
    def test_valid_base(self):
        v = StratixValidator(strict=False)
        r = v.validate(VALID_EVENT)
        assert r.layer_results["ocsf_base"] is True

    def test_missing_class_uid(self):
        event = {**VALID_EVENT}
        del event["class_uid"]
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid
        assert any("class_uid" in e for e in r.errors)

    def test_bad_timestamp(self):
        event = {**VALID_EVENT, "time": "not-a-date"}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid


class TestIntentLayer:
    def test_valid_intent(self):
        r = StratixValidator(strict=False).validate(VALID_EVENT)
        assert r.layer_results["intent"] is True

    def test_invalid_category(self):
        event = {**VALID_EVENT, "intent": {"category": "not_real"}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid

    def test_bad_technique_id(self):
        event = {**VALID_EVENT, "intent": {"category": "execution", "technique_id": "TXXX"}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid

    def test_confidence_score_out_of_range(self):
        event = {**VALID_EVENT, "intent": {"category": "execution", "confidence_score": 150}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid

    def test_valid_technique_with_subtechnique(self):
        event = {**VALID_EVENT, "intent": {"category": "execution", "technique_id": "T1059.001"}}
        r = StratixValidator(strict=False).validate(event)
        assert r.layer_results["intent"] is True


class TestSovereigntyLayer:
    def test_valid_sovereignty(self):
        r = StratixValidator(strict=False).validate(VALID_EVENT)
        assert r.layer_results["sovereignty"] is True

    def test_invalid_country_code(self):
        event = {**VALID_EVENT, "sovereignty": {"data_residency": "belgium"}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid

    def test_invalid_classification(self):
        event = {**VALID_EVENT, "sovereignty": {"classification": "top_secret"}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid

    def test_dora_ict_asset_must_be_bool(self):
        event = {**VALID_EVENT, "sovereignty": {"dora_ict_asset": "yes"}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid

    def test_access_log_entry_structure(self):
        entry = AccessLogEntry.create("analyst-001", "evt-abc", "incident-review")
        assert "signature" in entry
        assert "accessed_at" in entry
        event = {**VALID_EVENT,
                 "sovereignty": {**VALID_EVENT["sovereignty"], "access_log": [entry]}}
        r = StratixValidator(strict=False).validate(event)
        assert r.layer_results["sovereignty"] is True


class TestOTLayer:
    def test_valid_ot_event(self):
        event = {**VALID_EVENT, "ot": {"event_class": "industrial_protocol_event",
                                        "asset_id": "PLC-01", "purdue_level": 1}}
        r = StratixValidator(strict=False).validate(event)
        assert r.layer_results["ot"] is True

    def test_invalid_ot_class(self):
        event = {**VALID_EVENT, "ot": {"event_class": "invalid_class"}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid

    def test_invalid_purdue_level(self):
        event = {**VALID_EVENT, "ot": {"event_class": "scada_alarm", "purdue_level": 9}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid


class TestAILayer:
    def test_valid_ai_event(self):
        event = {**VALID_EVENT, "ai": {"event_class": "model_invocation",
                                        "model_id": "mistral-7b", "inference_location": "BE"}}
        r = StratixValidator(strict=False).validate(event)
        assert r.layer_results["ai"] is True

    def test_autonomous_action_missing_fields(self):
        event = {**VALID_EVENT, "ai": {"event_class": "autonomous_action"}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid

    def test_invalid_inference_location(self):
        event = {**VALID_EVENT, "ai": {"event_class": "model_invocation",
                                        "inference_location": "united_states"}}
        r = StratixValidator(strict=False).validate(event)
        assert not r.valid


class TestPipeline:
    def test_quarantine_mode(self):
        pipeline = StratixPipeline(strict=False, on_invalid="quarantine")
        pipeline.process(VALID_EVENT)
        bad = {"class_uid": 4001}  # missing required fields
        pipeline.process(bad)
        assert pipeline.stats["valid"] == 1
        assert pipeline.stats["quarantined"] == 1

    def test_passthrough_mode(self):
        pipeline = StratixPipeline(strict=False, on_invalid="passthrough")
        bad = {"class_uid": 4001}
        result = pipeline.process(bad)
        assert result is not None  # returned despite invalid
