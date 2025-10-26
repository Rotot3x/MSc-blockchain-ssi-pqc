"""Persistent storage for PQC keys and DIDs."""

import json
import os
import sqlite3
import logging
from typing import Dict, Any, Optional, List
import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

LOGGER = logging.getLogger(__name__)


class PersistentPQCStorage:
    """Persistent storage for PQC keys and DID documents."""

    def __init__(self, storage_dir: str = "/tmp/claude/pqc_storage"):
        """Initialize persistent storage.

        Args:
            storage_dir: Directory for storage files
        """
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)

        self.db_path = os.path.join(storage_dir, "pqc_storage.db")
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pqc_keys (
                    key_id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    private_key BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    metadata TEXT
                )
            """)

            # DIDs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pqc_dids (
                    did TEXT PRIMARY KEY,
                    did_document TEXT NOT NULL,
                    topic_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # Messages table (for local Hedera simulation)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hedera_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic_id TEXT NOT NULL,
                    message_data TEXT NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    consensus_timestamp TEXT NOT NULL,
                    running_hash TEXT NOT NULL
                )
            """)

            # Topics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hedera_topics (
                    topic_id TEXT PRIMARY KEY,
                    memo TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            conn.commit()

    def store_key_pair(
        self,
        key_id: str,
        algorithm: str,
        public_key: bytes,
        private_key: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Store a key pair persistently.

        Args:
            key_id: Unique key identifier
            algorithm: Algorithm name
            public_key: Public key bytes
            private_key: Private key bytes
            metadata: Optional metadata
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO pqc_keys
                (key_id, algorithm, public_key, private_key, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                key_id,
                algorithm,
                public_key,
                private_key,
                datetime.utcnow().isoformat(),
                json.dumps(metadata or {})
            ))

            conn.commit()

    def get_key_pair(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a key pair.

        Args:
            key_id: Key identifier

        Returns:
            Key pair data if found
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT key_id, algorithm, public_key, private_key, created_at, metadata
                FROM pqc_keys WHERE key_id = ?
            """, (key_id,))

            row = cursor.fetchone()
            if row:
                return {
                    "key_id": row[0],
                    "algorithm": row[1],
                    "public_key": row[2],
                    "private_key": row[3],
                    "created_at": row[4],
                    "metadata": json.loads(row[5])
                }

        return None

    def store_did_document(
        self,
        did: str,
        did_document: Dict[str, Any],
        topic_id: Optional[str] = None
    ):
        """Store a DID document persistently.

        Args:
            did: DID identifier
            did_document: DID document
            topic_id: Associated Hedera topic ID
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            now = datetime.utcnow().isoformat()

            cursor.execute("""
                INSERT OR REPLACE INTO pqc_dids
                (did, did_document, topic_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                did,
                json.dumps(did_document, indent=2),
                topic_id,
                now,
                now
            ))

            conn.commit()

    def get_did_document(self, did: str) -> Optional[Dict[str, Any]]:
        """Retrieve a DID document.

        Args:
            did: DID identifier

        Returns:
            DID document if found
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT did_document, topic_id, created_at, updated_at
                FROM pqc_dids WHERE did = ?
            """, (did,))

            row = cursor.fetchone()
            if row:
                did_doc = json.loads(row[0])
                did_doc["_storage_info"] = {
                    "topic_id": row[1],
                    "created_at": row[2],
                    "updated_at": row[3]
                }
                return did_doc

        return None

    def create_topic(self, topic_id: str, memo: str = ""):
        """Create a topic entry.

        Args:
            topic_id: Topic identifier
            memo: Topic memo
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO hedera_topics
                (topic_id, memo, created_at)
                VALUES (?, ?, ?)
            """, (
                topic_id,
                memo,
                datetime.utcnow().isoformat()
            ))

            conn.commit()

    def submit_message(
        self,
        topic_id: str,
        message_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Submit a message to a topic.

        Args:
            topic_id: Topic identifier
            message_data: Message data

        Returns:
            Submission result
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Get next sequence number
            cursor.execute("""
                SELECT MAX(sequence_number) FROM hedera_messages
                WHERE topic_id = ?
            """, (topic_id,))

            result = cursor.fetchone()
            sequence_number = (result[0] or 0) + 1

            # Calculate running hash
            running_hash = self._calculate_running_hash(topic_id, message_data)

            consensus_timestamp = datetime.utcnow().isoformat() + "Z"

            cursor.execute("""
                INSERT INTO hedera_messages
                (topic_id, message_data, sequence_number, consensus_timestamp, running_hash)
                VALUES (?, ?, ?, ?, ?)
            """, (
                topic_id,
                json.dumps(message_data),
                sequence_number,
                consensus_timestamp,
                running_hash
            ))

            conn.commit()

            return {
                "success": True,
                "topic_id": topic_id,
                "sequence_number": sequence_number,
                "consensus_timestamp": consensus_timestamp,
                "running_hash": running_hash
            }

    def get_topic_messages(self, topic_id: str) -> List[Dict[str, Any]]:
        """Get messages from a topic.

        Args:
            topic_id: Topic identifier

        Returns:
            List of messages
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT message_data, sequence_number, consensus_timestamp, running_hash
                FROM hedera_messages
                WHERE topic_id = ?
                ORDER BY sequence_number ASC
            """, (topic_id,))

            messages = []
            for row in cursor.fetchall():
                messages.append({
                    "topicId": topic_id,
                    "message": json.loads(row[0]),
                    "sequenceNumber": row[1],
                    "consensusTimestamp": row[2],
                    "runningHash": row[3]
                })

            return messages

    def _calculate_running_hash(self, topic_id: str, message_data: Dict[str, Any]) -> str:
        """Calculate running hash for message."""
        # Get previous hash
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT running_hash FROM hedera_messages
                WHERE topic_id = ?
                ORDER BY sequence_number DESC
                LIMIT 1
            """, (topic_id,))

            result = cursor.fetchone()
            previous_hash = result[0] if result else ""

        # Create new hash
        message_json = json.dumps(message_data, sort_keys=True)
        hash_input = f"{previous_hash}{message_json}".encode()

        return hashlib.sha384(hash_input).hexdigest()

    def generate_persistent_key_pair(self, algorithm: str, seed: Optional[str] = None) -> Dict[str, Any]:
        """Generate a persistent key pair using classical crypto as PQC placeholder.

        Args:
            algorithm: PQC algorithm name
            seed: Optional seed

        Returns:
            Key pair information
        """
        # For demonstration, use Ed25519 as PQC placeholder
        # In production, this would use actual PQC algorithms

        if seed:
            # Deterministic generation from seed
            seed_bytes = hashlib.sha256(seed.encode()).digest()
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes[:32])
        else:
            private_key = ed25519.Ed25519PrivateKey.generate()

        public_key = private_key.public_key()

        # Serialize keys
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Generate key ID
        key_id = self._generate_key_id(algorithm, public_bytes)

        # Store persistently
        self.store_key_pair(
            key_id=key_id,
            algorithm=algorithm,
            public_key=public_bytes,
            private_key=private_bytes,
            metadata={
                "is_pqc_placeholder": True,
                "actual_algorithm": "Ed25519",
                "pqc_algorithm": algorithm
            }
        )

        return {
            "key_id": key_id,
            "algorithm": algorithm,
            "public_key_bytes": public_bytes,
            "private_key_bytes": private_bytes
        }

    def sign_message(self, message: bytes, key_id: str) -> bytes:
        """Sign a message with stored key.

        Args:
            message: Message to sign
            key_id: Key identifier

        Returns:
            Signature bytes
        """
        key_data = self.get_key_pair(key_id)
        if not key_data:
            raise ValueError(f"Key not found: {key_id}")

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data["private_key"])
        signature = private_key.sign(message)

        return signature

    def verify_signature(self, message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """Verify a signature.

        Args:
            message: Original message
            signature: Signature to verify
            public_key_bytes: Public key bytes

        Returns:
            True if valid
        """
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def _generate_key_id(self, algorithm: str, public_key_bytes: bytes) -> str:
        """Generate key ID."""
        hash_input = f"{algorithm}:{base64.b64encode(public_key_bytes).decode()}".encode()
        key_hash = hashlib.sha256(hash_input).digest()[:8]
        return f"pqc-{algorithm.lower().replace('-', '')}-{base64.b64encode(key_hash).decode()[:10]}"

    def list_keys(self) -> List[Dict[str, Any]]:
        """List all stored keys."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT key_id, algorithm, created_at
                FROM pqc_keys
                ORDER BY created_at DESC
            """)

            return [
                {"key_id": row[0], "algorithm": row[1], "created_at": row[2]}
                for row in cursor.fetchall()
            ]

    def list_dids(self) -> List[Dict[str, Any]]:
        """List all stored DIDs."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT did, topic_id, created_at, updated_at
                FROM pqc_dids
                ORDER BY created_at DESC
            """)

            return [
                {
                    "did": row[0],
                    "topic_id": row[1],
                    "created_at": row[2],
                    "updated_at": row[3]
                }
                for row in cursor.fetchall()
            ]

    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Count keys
            cursor.execute("SELECT COUNT(*) FROM pqc_keys")
            key_count = cursor.fetchone()[0]

            # Count DIDs
            cursor.execute("SELECT COUNT(*) FROM pqc_dids")
            did_count = cursor.fetchone()[0]

            # Count topics
            cursor.execute("SELECT COUNT(*) FROM hedera_topics")
            topic_count = cursor.fetchone()[0]

            # Count messages
            cursor.execute("SELECT COUNT(*) FROM hedera_messages")
            message_count = cursor.fetchone()[0]

            return {
                "keys": key_count,
                "dids": did_count,
                "topics": topic_count,
                "messages": message_count,
                "storage_path": self.db_path
            }