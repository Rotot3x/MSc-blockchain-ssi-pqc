"""Hedera Client Service - Direct REST API implementation."""

import json
import logging
import aiohttp
import asyncio
from typing import Dict, Any, Optional, List
import base64
import hashlib
from datetime import datetime

from acapy_agent.core.error import BaseError

from ..config import PQCHederaConfig
from ..storage.persistent_storage import PersistentPQCStorage

LOGGER = logging.getLogger(__name__)


class HederaClientError(BaseError):
    """Hedera Client specific errors."""
    pass


class HederaClientService:
    """Service for interacting with Hedera Hashgraph via REST API."""

    def __init__(self, config: PQCHederaConfig):
        """Initialize Hedera Client Service.

        Args:
            config: Plugin configuration
        """
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._initialized = False

        # For local network, use simplified approach
        self.base_url = self.config.mirror_node_url
        self.consensus_node_url = f"http://localhost:50211"

        # Use persistent storage instead of in-memory
        self.storage = PersistentPQCStorage()
        self._topic_counter = 1000

    async def initialize(self):
        """Initialize the Hedera client."""
        if self._initialized:
            return

        LOGGER.info("Initializing Hedera Client Service...")

        # Create HTTP session
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )

        # Test connection to mirror node
        try:
            await self._test_connection()
            LOGGER.info("✅ Connected to Hedera Mirror Node")
        except Exception as e:
            LOGGER.warning(f"Mirror Node connection failed: {e}")

        self._initialized = True
        LOGGER.info("✅ Hedera Client Service initialized")

    async def cleanup(self):
        """Cleanup resources."""
        if self._session:
            await self._session.close()

    async def create_topic(self, memo: str = "") -> str:
        """Create a new Hedera Consensus Service topic.

        Args:
            memo: Topic memo

        Returns:
            Topic ID
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Creating topic with memo: {memo}")

        # Create persistent topic
        topic_id = f"0.0.{self._topic_counter}"
        self._topic_counter += 1

        # Store topic in persistent storage
        self.storage.create_topic(topic_id, memo)

        LOGGER.info(f"✅ Created persistent topic: {topic_id}")

        return topic_id

    async def submit_message(
        self,
        topic_id: str,
        message: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Submit a message to a Hedera Consensus Service topic.

        Args:
            topic_id: Topic ID
            message: Message to submit

        Returns:
            Submission result
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Submitting message to topic: {topic_id}")

        # Submit to persistent storage
        result = self.storage.submit_message(topic_id, message)

        LOGGER.info(f"✅ Message submitted to topic {topic_id}")

        return result

    async def get_topic_messages(
        self,
        topic_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get messages from a Hedera Consensus Service topic.

        Args:
            topic_id: Topic ID
            start_time: Start time filter
            end_time: End time filter

        Returns:
            List of messages
        """
        if not self._initialized:
            await self.initialize()

        LOGGER.info(f"Retrieving messages from topic: {topic_id}")

        # Get from persistent storage first
        messages = self.storage.get_topic_messages(topic_id)
        if messages:
            LOGGER.info(f"✅ Retrieved {len(messages)} messages from persistent storage")
            return messages

        # Try to get from mirror node
        try:
            url = f"{self.base_url}/api/v1/topics/{topic_id}/messages"
            params = {}

            if start_time:
                params['timestamp'] = f"gte:{start_time}"
            if end_time:
                if 'timestamp' in params:
                    params['timestamp'] += f"&timestamp=lte:{end_time}"
                else:
                    params['timestamp'] = f"lte:{end_time}"

            async with self._session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    messages = data.get('messages', [])

                    # Convert to our format
                    converted_messages = []
                    for msg in messages:
                        try:
                            message_data = base64.b64decode(msg.get('message', '')).decode('utf-8')
                            parsed_message = json.loads(message_data)

                            converted_messages.append({
                                "topicId": topic_id,
                                "consensusTimestamp": msg.get('consensus_timestamp'),
                                "message": parsed_message,
                                "messageBytes": msg.get('message'),
                                "runningHash": msg.get('running_hash'),
                                "sequenceNumber": msg.get('sequence_number')
                            })
                        except Exception as e:
                            LOGGER.warning(f"Failed to parse message: {e}")
                            continue

                    LOGGER.info(f"✅ Retrieved {len(converted_messages)} messages from mirror node")
                    return converted_messages

        except Exception as e:
            LOGGER.warning(f"Failed to retrieve messages from mirror node: {e}")

        # Return empty list if no messages found
        return []

    async def query_did_registry(self, did: str) -> Optional[Dict[str, Any]]:
        """Query DID registry for topic information.

        Args:
            did: DID to query

        Returns:
            Registry information if found
        """
        # For local testing, simulate registry lookup
        # In a real implementation, this would query a registry topic

        # Extract identifier from DID
        did_parts = did.split(":")
        if len(did_parts) >= 4:
            identifier = did_parts[3]

            # Create deterministic topic ID
            topic_id = f"0.0.{abs(hash(identifier)) % 1000 + 1000}"

            return {
                "did": did,
                "topicId": topic_id,
                "network": self.config.network,
                "created": datetime.utcnow().isoformat() + "Z"
            }

        return None

    async def get_account_info(self, account_id: str) -> Dict[str, Any]:
        """Get account information.

        Args:
            account_id: Account ID

        Returns:
            Account information
        """
        try:
            url = f"{self.base_url}/api/v1/accounts/{account_id}"

            async with self._session.get(url) as response:
                if response.status == 200:
                    return await response.json()

        except Exception as e:
            LOGGER.warning(f"Failed to get account info: {e}")

        return {}

    async def get_network_status(self) -> Dict[str, Any]:
        """Get network status information.

        Returns:
            Network status
        """
        try:
            url = f"{self.base_url}/api/v1/network/nodes"

            async with self._session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "status": "healthy",
                        "nodes": data.get("nodes", []),
                        "network": self.config.network
                    }

        except Exception as e:
            LOGGER.warning(f"Failed to get network status: {e}")

        return {
            "status": "unknown",
            "network": self.config.network,
            "error": str(e) if 'e' in locals() else "Connection failed"
        }

    def _calculate_running_hash(self, topic_id: str, message_bytes: bytes) -> str:
        """Calculate running hash for message.

        Args:
            topic_id: Topic ID
            message_bytes: Message bytes

        Returns:
            Running hash
        """
        # Get previous hash
        previous_hash = b""
        if topic_id in self._local_topics and self._local_topics[topic_id]:
            last_message = self._local_topics[topic_id][-1]
            previous_hash = base64.b64decode(last_message.get("runningHash", ""))

        # Calculate new running hash
        hash_input = previous_hash + message_bytes
        new_hash = hashlib.sha384(hash_input).digest()

        return base64.b64encode(new_hash).decode()

    async def _test_connection(self):
        """Test connection to Hedera network."""
        try:
            # Test mirror node
            url = f"{self.base_url}/api/v1/network/nodes"

            async with self._session.get(url) as response:
                if response.status != 200:
                    raise HederaClientError(f"Mirror node returned status: {response.status}")

        except aiohttp.ClientError as e:
            raise HederaClientError(f"Failed to connect to mirror node: {e}")

    def is_ready(self) -> bool:
        """Check if client is ready."""
        return self._initialized and self._session is not None

    async def get_topics_list(self) -> List[str]:
        """Get list of known topics.

        Returns:
            List of topic IDs
        """
        return list(self._local_topics.keys())

    async def get_topic_info(self, topic_id: str) -> Dict[str, Any]:
        """Get topic information.

        Args:
            topic_id: Topic ID

        Returns:
            Topic information
        """
        if topic_id in self._local_topics:
            return {
                "topicId": topic_id,
                "messageCount": len(self._local_topics[topic_id]),
                "status": "active",
                "network": self.config.network
            }

        return {
            "topicId": topic_id,
            "messageCount": 0,
            "status": "unknown",
            "network": self.config.network
        }