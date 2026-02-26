"""
STRATIX SDK — Mapper test suite
© 2026 Intelligent Consulting BV. All rights reserved.
"""

from stratix.mappers import (
    ECSToStratix, CIMToStratix, ASIMToStratix,
    ModbusToStratix, DNP3ToStratix, OPCUAToStratix,
    get_mapper,
)


def test_ecs_mapper():
    raw = {
        "@timestamp": "2026-02-26T14:00:00Z",
        "event": {"category": ["authentication"], "risk_score": 78},
        "tags": ["T1078"],
        "host": {"geo": {"country_iso_code": "BE"}},
        "agent": {"version": "8.12.0"},
    }
    result = ECSToStratix().map(raw)
    assert result["intent"]["category"] == "credential_access"
    assert result["intent"]["technique_id"] == "T1078"
    assert result["sovereignty"]["data_residency"] == "BE"


def test_modbus_write_mapper():
    frame = {"timestamp": "2026-02-26T14:00:00Z", "function_code": 0x06,
             "src_ip": "192.168.1.5", "dst_ip": "192.168.1.1"}
    result = ModbusToStratix().map(frame, asset_id="PLC-01", purdue_level=1)
    assert result["ot"]["is_write_operation"] is True
    assert result["intent"]["category"] == "execution"
    assert result["ot"]["purdue_level"] == 1


def test_dnp3_high_risk_mapper():
    frame = {"timestamp": "2026-02-26T14:00:00Z", "function_code": 0x05}
    result = DNP3ToStratix().map(frame, asset_id="RTU-01", data_residency="DE")
    assert result["intent"]["category"] == "impact"
    assert "critical_infrastructure" in result["intent"]["blast_radius"]
    assert result["sovereignty"]["classification"] == "sovereign"


def test_opcua_write_mapper():
    event = {"timestamp": "2026-02-26T14:00:00Z", "service_type": "Write",
             "node_id": "ns=2;s=Reactor.Setpoint", "client_ip": "10.0.0.5"}
    result = OPCUAToStratix().map(event, asset_id="HIST-01")
    assert result["intent"]["confidence_score"] == 75
    assert result["ot"]["service_type"] == "Write"


def test_get_mapper_factory():
    for schema in ["ecs", "cim", "asim", "modbus", "dnp3", "opc-ua"]:
        m = get_mapper(schema)
        assert hasattr(m, "map")
        assert hasattr(m, "map_batch")
