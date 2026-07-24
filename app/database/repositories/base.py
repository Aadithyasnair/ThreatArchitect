import sqlite3
import logging
from typing import List, Optional, Any, Generic, TypeVar
from app.core.interfaces import IRepository
from app.database.connection import DatabaseConnection

logger = logging.getLogger("BaseRepository")
T = TypeVar('T')

class BaseRepository(IRepository[T], Generic[T]):
    """Generic SQLite repository implementation."""
    
    def __init__(self, db_conn: DatabaseConnection, table_name: str) -> None:
        self.db_conn = db_conn
        self.table_name = table_name

    def _get_connection(self) -> sqlite3.Connection:
        return self.db_conn.connect()

    def get_by_id(self, entity_id: Any) -> Optional[T]:
        conn = self._get_connection()
        cursor = conn.cursor()
        query = f"SELECT * FROM {self.table_name} WHERE id = ?"
        try:
            cursor.execute(query, (entity_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            logger.error(f"Error reading from {self.table_name}: {e}")
            return None

    def get_all(self) -> List[T]:
        conn = self._get_connection()
        cursor = conn.cursor()
        query = f"SELECT * FROM {self.table_name} ORDER BY id DESC"
        try:
            cursor.execute(query)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error listing {self.table_name}: {e}")
            return []

    def delete(self, entity_id: Any) -> None:
        conn = self._get_connection()
        cursor = conn.cursor()
        query = f"DELETE FROM {self.table_name} WHERE id = ?"
        try:
            cursor.execute(query, (entity_id,))
            conn.commit()
            logger.debug(f"Deleted row {entity_id} from {self.table_name}")
        except sqlite3.Error as e:
            logger.error(f"Error deleting from {self.table_name}: {e}")
            conn.rollback()
            raise
