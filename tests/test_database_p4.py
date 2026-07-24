"""
tests/test_database_p4 — Unit tests for SQLite schemas and writes.
"""

import os
import sqlite3
import pytest
from app.database.connection import DatabaseConnection


def test_sqlite_schema_creation(tmp_path) -> None:
    """Verifies that all Phase 4 tables are created during initialization."""
    db_file = os.path.join(tmp_path, "test_threat_architect.db")
    db_conn = DatabaseConnection(db_file)
    
    # Connect triggers _initialize_schema
    conn = db_conn.connect()
    
    # Query sqlite_master to verify tables exist
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    assert "incidents" in tables
    assert "timeline_events" in tables
    assert "threat_history" in tables
    assert "compliance_details" in tables
    assert "reports" in tables
    
    db_conn.disconnect()


def test_incident_insert_and_fetch(tmp_path) -> None:
    """Verifies write and read operations on incidents and timelines."""
    db_file = os.path.join(tmp_path, "test_threat_architect.db")
    db_conn = DatabaseConnection(db_file)
    conn = db_conn.connect()
    cursor = conn.cursor()
    
    # Insert threat history
    cursor.execute(
        "INSERT INTO threat_history (anomaly_score, classifier_confidence, predicted_class, threat_score) VALUES (?, ?, ?, ?)",
        (0.85, 0.92, "SYN Flood", 88)
    )
    
    # Insert timeline event
    cursor.execute(
        "INSERT INTO timeline_events (event_time, message, event_type) VALUES (?, ?, ?)",
        ("12:00:15", "Blocked attacker traffic.", "BLOCKED")
    )
    
    # Insert incident
    cursor.execute("""
        INSERT INTO incidents (attack_category, threat_score, threat_level, attacker_host, affected_host, affected_service, remediation_plan, explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, ("SYN Flood", 88, "CRITICAL", "10.0.2.12", "10.0.1.10", "80", "{}", "Analysis explanation."))
    
    conn.commit()
    
    # Retrieve and verify
    cursor.execute("SELECT * FROM threat_history ORDER BY id DESC LIMIT 1")
    th = cursor.fetchone()
    assert th["predicted_class"] == "SYN Flood"
    assert th["threat_score"] == 88
    
    cursor.execute("SELECT * FROM timeline_events ORDER BY id DESC LIMIT 1")
    te = cursor.fetchone()
    assert te["event_type"] == "BLOCKED"
    assert te["message"] == "Blocked attacker traffic."
    
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1")
    inc = cursor.fetchone()
    assert inc["attack_category"] == "SYN Flood"
    assert inc["threat_level"] == "CRITICAL"
    
    db_conn.disconnect()
