"""
PQC Message Handler

Simplified message handler for PQC operations.
"""

import logging
from aries_cloudagent.messaging.base_handler import BaseHandler

LOGGER = logging.getLogger(__name__)

class PQCHandler(BaseHandler):
    """Handler for PQC-related messages."""

    async def handle(self, context, responder):
        """Handle PQC-related messages."""
        LOGGER.debug("Processing PQC message")

        message = context.message
        LOGGER.debug(f"Received message type: {getattr(message, '_type', 'unknown')}")