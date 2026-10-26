import sqlite3
import json
from datetime import datetime

DB_NAME = "threatlens.db"


def create_database():
    connection = sqlite3.connect(DB_NAME)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            port INTEGER,
            evidence TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_incidents(alerts):
    connection = sqlite3.connect(DB_NAME)

    for alert in alerts:
        connection.execute("""
            INSERT INTO incidents (
                timestamp,
                alert_type,
                source_ip,
                destination_ip,
                port,
                evidence
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            alert.get("Type", "Unknown"),
            alert.get("Source IP", ""),
            alert.get("Destination IP", ""),
            alert.get("Port"),
            alert.get("Evidence", "")
        ))

    connection.commit()
    connection.close()


def get_incidents():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row

    rows = connection.execute("""
        SELECT * FROM incidents
        ORDER BY id DESC
    """).fetchall()

    incidents = [dict(row) for row in rows]
    connection.close()

    return incidents