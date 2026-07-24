import sqlite3
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("Database")

class DatabaseConnection:
    """Manages connection to local SQLite database and schemas."""
    
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        
    def connect(self) -> sqlite3.Connection:
        """Establish database connection and return it. Restores from backup on corruption."""
        if self._conn is not None:
            return self._conn
            
        path = Path(self.db_path)
        if not path.parent.exists() and path.parent != Path('.'):
            path.parent.mkdir(parents=True, exist_ok=True)
            
        logger.info(f"Connecting to database at {self.db_path}")
        
        try:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._initialize_schema()
        except (sqlite3.DatabaseError, sqlite3.OperationalError) as exc:
            logger.error(f"Database corruption or access error detected: {exc}. Restoring from backup...")
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

            # Attempt backup restore
            backup_path = self.db_path + ".bak"
            import shutil
            if os.path.exists(backup_path):
                try:
                    shutil.copy2(backup_path, self.db_path)
                    logger.info("Restored database file from backup copy.")
                    self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
                    self._conn.row_factory = sqlite3.Row
                    self._conn.execute("PRAGMA foreign_keys = ON;")
                    self._initialize_schema()
                    return self._conn
                except Exception as restore_exc:
                    logger.error(f"Failed to restore database from backup: {restore_exc}")
            
            # If no backup or restore failed, rename to corrupted and start fresh
            corrupted_rename = self.db_path + ".corrupted"
            try:
                if os.path.exists(self.db_path):
                    os.rename(self.db_path, corrupted_rename)
                    logger.warning(f"Renamed corrupted database file to {corrupted_rename}")
            except Exception as rename_exc:
                logger.error(f"Failed to rename corrupted database: {rename_exc}")

            # Recreate fresh DB
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._initialize_schema()

        # Database is healthy, create/refresh backup
        try:
            import shutil
            shutil.copy2(self.db_path, self.db_path + ".bak")
            logger.debug("Database backup created successfully.")
        except Exception as backup_exc:
            logger.warning(f"Could not create database backup: {backup_exc}")

        return self._conn

    def disconnect(self) -> None:
        """Close connection if open."""
        if self._conn:
            logger.info("Closing database connection.")
            self._conn.close()
            self._conn = None

    def _initialize_schema(self) -> None:
        """Create basic tables if they do not exist."""
        cursor = self._conn.cursor()
        
        # Table for storing captured traffic stats
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                packets_captured INTEGER,
                packets_per_second INTEGER,
                anomaly_score REAL,
                classifier_confidence REAL,
                attack_type TEXT,
                threat_level TEXT
            );
        """)
        
        # Table for compliance checklists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                framework TEXT,
                passed_rules INTEGER,
                failed_rules INTEGER,
                score REAL,
                status TEXT
            );
        """)

        # Table for compliance individual checks details
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                framework TEXT,
                control_id TEXT,
                status TEXT,
                reason TEXT,
                improvement TEXT
            );
        """)

        # Table for system logs / actions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                module TEXT,
                level TEXT,
                message TEXT
            );
        """)

        # Table for Threat incidents
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                attack_category TEXT,
                threat_score INTEGER,
                threat_level TEXT,
                attacker_host TEXT,
                affected_host TEXT,
                affected_service TEXT,
                remediation_plan TEXT,
                explanation TEXT
            );
        """)

        # Table for Threat timeline events
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_time TEXT,
                message TEXT,
                event_type TEXT
            );
        """)

        # Table for continuous threat metrics history (timeline metrics)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                anomaly_score REAL,
                classifier_confidence REAL,
                predicted_class TEXT,
                threat_score INTEGER
            );
        """)

        # Table for PDF reports
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                filename TEXT,
                file_path TEXT,
                summary TEXT
            );
        """)

        # Table for persisted firewall rules
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                port INTEGER,
                protocol TEXT,
                action TEXT,
                description TEXT
            );
        """)
        
        self._conn.commit()
        logger.info("Database schemas verified/initialized.")
