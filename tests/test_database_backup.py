import os
import pytest
import sqlite3
from app.database.connection import DatabaseConnection


def test_database_backup_and_recovery():
    """Verify db backup creation and auto restoration from backup when DB is corrupted."""
    db_path = "test_backup.db"
    backup_path = db_path + ".bak"

    # Clean previous
    for p in [db_path, backup_path]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

    # Initialize connection
    db = DatabaseConnection(db_path)
    conn = db.connect()
    
    # Verify backup exists
    assert os.path.exists(backup_path)
    db.disconnect()

    # Corrupt database manually by writing garbage to it
    with open(db_path, "w", encoding="utf-8") as f:
        f.write("CORRUPT GARBAGE TEXT")

    # Connect again - should recover from backup
    db2 = DatabaseConnection(db_path)
    conn2 = db2.connect()
    
    # Should establish connection and query schemas successfully
    cursor = conn2.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    assert "incidents" in tables
    assert "network_metrics" in tables

    db2.disconnect()

    # Clean up files
    for p in [db_path, backup_path, db_path + ".corrupted"]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
