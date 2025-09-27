"""PQC Askar Wallet Service for creating PQC-enabled Askar wallets."""

import logging
from typing import Dict, Optional, Any

from acapy_agent.core.profile import Profile
from acapy_agent.multitenant.base import BaseMultitenantManager
from acapy_agent.wallet.models.wallet_record import WalletRecord
from acapy_agent.wallet.error import WalletError
from acapy_agent.core.error import BaseError

from ..config import PQCConfig
from ..key_types import PQC_KEY_TYPES, DEFAULT_PQC_SIGNATURE_KEY_TYPE

LOGGER = logging.getLogger(__name__)


class PQCAskarWalletService:
    """Service for creating and managing PQC-enabled Askar wallets."""

    def __init__(self, config: PQCConfig):
        """Initialize PQC Askar Wallet Service.

        Args:
            config: PQC configuration
        """
        self.config = config

    async def create_pqc_askar_wallet(
        self,
        profile: Profile,
        wallet_name: str,
        wallet_key: str,
        label: Optional[str] = None,
        image_url: Optional[str] = None,
        key_management_mode: str = WalletRecord.MODE_MANAGED,
        wallet_webhook_urls: Optional[list] = None,
        wallet_dispatch_type: str = "default",
        pqc_algorithm: str = DEFAULT_PQC_SIGNATURE_KEY_TYPE,
        enable_anoncreds: bool = True,
        extra_settings: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a new PQC-enabled Askar wallet.

        Args:
            profile: Current profile
            wallet_name: Name for the new wallet
            wallet_key: Encryption key for the wallet
            label: Optional label for the wallet
            image_url: Optional image URL for the wallet
            key_management_mode: Key management mode (managed/unmanaged)
            wallet_webhook_urls: List of webhook URLs for the wallet
            wallet_dispatch_type: Webhook dispatch type
            pqc_algorithm: PQC algorithm to use as default
            enable_anoncreds: Whether to enable AnonCreds support
            extra_settings: Additional wallet settings

        Returns:
            Dictionary containing wallet information and access token

        Raises:
            WalletError: If wallet creation fails
        """
        try:
            LOGGER.info(f"Creating PQC-enabled Askar wallet: {wallet_name}")

            # Validate PQC algorithm
            if not self._is_valid_pqc_algorithm(pqc_algorithm):
                raise WalletError(f"Invalid PQC algorithm: {pqc_algorithm}")

            # Prepare wallet settings with PQC configuration
            base_wallet_type = profile.settings.get("wallet.type", "askar")

            # Ensure we're using Askar for PQC support
            if base_wallet_type != "askar":
                LOGGER.warning(f"Base wallet type is {base_wallet_type}, but PQC requires Askar")
                wallet_type = "askar"
            else:
                wallet_type = base_wallet_type

            settings = {
                "wallet.type": wallet_type,
                "wallet.name": wallet_name,
                "wallet.key": wallet_key,
                "wallet.webhook_urls": wallet_webhook_urls or [],
                "wallet.dispatch_type": wallet_dispatch_type,
                # PQC-specific settings
                "pqc.enabled": True,
                "pqc.default_signature_algorithm": pqc_algorithm,
                "pqc.enable_hybrid_mode": self.config.enable_hybrid_mode,
                "pqc.anoncreds_enabled": enable_anoncreds,
            }

            # Add optional settings
            if label:
                settings["default_label"] = label
            if image_url:
                settings["image_url"] = image_url

            # Add extra settings
            if extra_settings:
                settings.update(extra_settings)

            # Get multitenant manager
            multitenant_mgr = profile.inject(BaseMultitenantManager)

            # Create the wallet
            wallet_record = await multitenant_mgr.create_wallet(
                settings, key_management_mode
            )

            # Create auth token
            token = await multitenant_mgr.create_auth_token(wallet_record, wallet_key)

            # Get wallet profile for additional setup
            wallet_profile = await multitenant_mgr.get_wallet_profile(
                profile.context, wallet_record, extra_settings=settings
            )

            # Initialize PQC services in the new wallet
            await self._initialize_pqc_services(wallet_profile, pqc_algorithm)

            # Initialize AnonCreds integration if enabled
            if enable_anoncreds:
                await self._initialize_anoncreds_integration(wallet_profile)

            LOGGER.info(f"✅ Successfully created PQC wallet: {wallet_name}")

            # Format response
            wallet_info = self._format_wallet_record(wallet_record)
            wallet_info["pqc_config"] = {
                "enabled": True,
                "default_algorithm": pqc_algorithm,
                "hybrid_mode": self.config.enable_hybrid_mode,
                "anoncreds_enabled": enable_anoncreds,
                "supported_algorithms": [kt.key_type for kt in PQC_KEY_TYPES]
            }

            return {
                "wallet_id": wallet_record.wallet_id,
                "wallet_info": wallet_info,
                "token": token,
                "created_at": wallet_record.created_at,
                "updated_at": wallet_record.updated_at,
            }

        except BaseError as e:
            LOGGER.error(f"Failed to create PQC Askar wallet: {e}")
            raise WalletError(f"PQC Askar wallet creation failed: {e}")

        except Exception as e:
            LOGGER.error(f"Unexpected error creating PQC Askar wallet: {e}")
            raise WalletError(f"Unexpected error in wallet creation: {e}")

    async def _initialize_pqc_services(self, wallet_profile: Profile, default_algorithm: str):
        """Initialize PQC services in the new wallet.

        Args:
            wallet_profile: The new wallet's profile
            default_algorithm: Default PQC algorithm to configure
        """
        try:
            # Import services
            from .pqc_crypto_service import PQCCryptoService
            from .pqc_wallet_service import PQCWalletService
            from .pqc_did_service import PQCDidService

            # Initialize services
            crypto_service = PQCCryptoService(self.config)
            await crypto_service.initialize()

            wallet_service = PQCWalletService(self.config)
            did_service = PQCDidService(self.config)

            # Bind services to the wallet's context
            wallet_profile.context.injector.bind_instance(PQCCryptoService, crypto_service)
            wallet_profile.context.injector.bind_instance(PQCWalletService, wallet_service)
            wallet_profile.context.injector.bind_instance(PQCDidService, did_service)

            LOGGER.info(f"🔐 Initialized PQC services in wallet with default algorithm: {default_algorithm}")

        except Exception as e:
            LOGGER.warning(f"Failed to initialize PQC services in wallet: {e}")
            # Don't fail wallet creation if PQC service init fails

    async def _initialize_anoncreds_integration(self, wallet_profile: Profile):
        """Initialize AnonCreds integration with PQC support in the new wallet.

        Args:
            wallet_profile: The new wallet's profile
        """
        try:
            from ..anoncreds_integration import setup_pqc_anoncreds_integration

            # Setup AnonCreds integration for this wallet
            await setup_pqc_anoncreds_integration(wallet_profile.context)

            LOGGER.info("🔐 Initialized AnonCreds PQC integration in wallet")

        except Exception as e:
            LOGGER.warning(f"Failed to initialize AnonCreds integration: {e}")
            # Don't fail wallet creation if AnonCreds integration fails

    def _is_valid_pqc_algorithm(self, algorithm: str) -> bool:
        """Check if the specified algorithm is a valid PQC algorithm.

        Args:
            algorithm: Algorithm name to validate

        Returns:
            True if valid PQC algorithm
        """
        return algorithm in [kt.key_type for kt in PQC_KEY_TYPES]

    def _format_wallet_record(self, wallet_record: WalletRecord) -> Dict[str, Any]:
        """Format wallet record for response.

        Args:
            wallet_record: Wallet record to format

        Returns:
            Formatted wallet information
        """
        wallet_info = wallet_record.serialize()

        # Hide sensitive wallet key
        if "wallet.key" in wallet_info.get("settings", {}):
            del wallet_info["settings"]["wallet.key"]

        return wallet_info

    async def get_pqc_wallet_info(
        self,
        profile: Profile,
        wallet_id: str
    ) -> Dict[str, Any]:
        """Get information about a PQC wallet.

        Args:
            profile: Current profile
            wallet_id: ID of the wallet to get info for

        Returns:
            Wallet information including PQC configuration

        Raises:
            WalletError: If wallet not found or access fails
        """
        try:
            multitenant_mgr = profile.inject(BaseMultitenantManager)
            wallet_record = await multitenant_mgr.get_wallet_record(wallet_id)

            # Check if this is a PQC wallet
            is_pqc = wallet_record.settings.get("pqc.enabled", False)

            wallet_info = self._format_wallet_record(wallet_record)

            if is_pqc:
                wallet_info["pqc_config"] = {
                    "enabled": True,
                    "default_algorithm": wallet_record.settings.get("pqc.default_signature_algorithm"),
                    "hybrid_mode": wallet_record.settings.get("pqc.enable_hybrid_mode", False),
                    "anoncreds_enabled": wallet_record.settings.get("pqc.anoncreds_enabled", True),
                    "supported_algorithms": [kt.key_type for kt in PQC_KEY_TYPES]
                }
            else:
                wallet_info["pqc_config"] = {"enabled": False}

            return wallet_info

        except Exception as e:
            LOGGER.error(f"Failed to get PQC wallet info: {e}")
            raise WalletError(f"Failed to get wallet information: {e}")

    async def list_pqc_wallets(self, profile: Profile) -> list:
        """List all PQC-enabled wallets.

        Args:
            profile: Current profile

        Returns:
            List of PQC wallet information
        """
        try:
            multitenant_mgr = profile.inject(BaseMultitenantManager)

            # Get all wallets (this method might need adjustment based on actual API)
            # For now, we'll return a placeholder
            LOGGER.info("Listing PQC wallets")

            # TODO: Implement actual wallet listing logic
            # This would require querying the wallet storage for PQC-enabled wallets

            return []

        except Exception as e:
            LOGGER.error(f"Failed to list PQC wallets: {e}")
            raise WalletError(f"Failed to list wallets: {e}")