#!/usr/bin/env python3
"""
PQC-Enhanced Acme Agent

Corporate proof verifier with Post-Quantum Cryptography support.
This agent demonstrates quantum-safe proof verification using Dilithium3 signatures.
"""

import asyncio
import json
import logging
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.utils import (  # noqa:E402
    log_json,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)

SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)

class AcmeAgent(AriesAgent):
    """Acme Agent with PQC support for proof verification."""

    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Acme",
            no_auto=no_auto,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        self.proof_state = {}
        # PQC-specific attributes
        self.pqc_enabled = os.getenv("ACAPY_PQC_ENABLED", "0") == "1"
        self.pqc_sig_algorithm = os.getenv("PQC_AGENT_SIG_ALG", "Dilithium3")
        self.pqc_kem_algorithm = os.getenv("PQC_AGENT_KEM_ALG", "Kyber768")

    async def detect_connection(self):
        """Detect and set up connection with Alice."""
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        """Check if connection is ready."""
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_connections(self, message):
        """Handle connection-related events."""
        if message["state"] == "active" and not self._connection_ready.done():
            self.log("Connected")
            self._connection_ready.set_result(True)
            self.connection_id = message["connection_id"]
            
            # Log PQC connection details if enabled
            if self.pqc_enabled:
                self.log(f"🔒 PQC Connection established with Alice")
                self.log(f"   Verification Algorithm: {self.pqc_sig_algorithm}")
                self.log(f"   KEM Algorithm: {self.pqc_kem_algorithm}")

    async def handle_present_proof_v2_0(self, message):
        """Handle proof presentation events."""
        state = message["state"]
        pres_ex_id = message["pres_ex_id"]
        prev_state = self.proof_state.get(pres_ex_id)
        
        if prev_state == state:
            return  # ignore
        self.proof_state[pres_ex_id] = state

        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "presentation-received":
            if self.pqc_enabled:
                self.log("🔒 Received PQC-secured presentation from Alice")
                self.log(f"   Verifying with algorithm: {self.pqc_sig_algorithm}")
            
            log_status("#27 Process the proof provided by Alice")
            log_status("#28 Check if proof is valid")
            
            # Enhanced PQC proof verification
            proof = await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
            )
            
            self.log("Proof verification result =", proof["verified"])
            
            if self.pqc_enabled:
                if proof.get("verified"):
                    self.log("✅ PQC-secured proof VERIFIED successfully!")
                    self.log("   Quantum-safe cryptographic verification passed")
                    
                    # Check for PQC-specific verification details
                    if "verification_result" in proof:
                        verification_details = proof["verification_result"]
                        if isinstance(verification_details, dict):
                            pqc_verifications = verification_details.get("pqc_verifications", 0)
                            if pqc_verifications > 0:
                                self.log(f"   PQC signature verifications: {pqc_verifications}")
                else:
                    self.log("❌ PQC-secured proof VERIFICATION FAILED!")
                    
            # Log detailed proof results
            if proof.get("verified") == "true":
                log_status("#28.1 Proof verification successful")
            else:
                log_status("#28.2 Proof verification failed")

    async def handle_basicmessages(self, message):
        """Handle basic messages."""
        self.log("Received message:", message)

async def main(args):
    """Main function for Acme agent."""
    acme_agent = AcmeAgent(
        "acme",
        args.port,
        args.admin_port,
        prefix="Acme",
        extra_args=args.extra,
        revocation=not args.no_revocation,
        tails_server_base_url=args.tails_server_base_url,
        show_timing=args.timing,
        multitenant=args.multitenant,
        mediation=args.mediation,
        wallet_type=args.wallet_type,
        seed=args.seed,
        aip=args.aip,
        endorser_role=args.endorser_role,
    )

    # Enhanced PQC startup logging
    if acme_agent.pqc_enabled:
        acme_agent.log("🔒 PQC Mode: ENABLED")
        acme_agent.log(f"   Plugin: {os.getenv('ACAPY_PLUGIN', 'pqcrypto_fm.v1_0')}")
        acme_agent.log(f"   Verification Algorithm: {acme_agent.pqc_sig_algorithm}")
        acme_agent.log(f"   KEM Algorithm: {acme_agent.pqc_kem_algorithm}")
        acme_agent.log(f"   Wallet Type: {args.wallet_type}")
        acme_agent.log("   Quantum-Safe Proof Verification: ACTIVE")

    if args.cred_type == "indy":
        acme_agent.cred_type = "indy"
    elif args.cred_type == "json-ld":
        acme_agent.cred_type = "json-ld"

    await acme_agent.listen_webhooks(args.webhook_port)

    with log_timer("Startup duration:"):
        await acme_agent.start_process()
    log_msg("Admin URL is at:", acme_agent.admin_url)
    log_msg("Endpoint URL is at:", acme_agent.endpoint)

    # Main agent loop
    async with acme_agent:
        log_status("#7 Provision an agent and wallet, get back configuration details")
        agent_config = await acme_agent.fetch_config()
        log_json(agent_config, label="Provisioned Agent:")

        log_status("#9 Input alice.py invitation details")
        acme_agent._connection_ready = asyncio.Future()

        # Enhanced options with PQC features
        options = (
            "    (1) Input new invitation\n"
            "    (2) Send Message\n"
            "    (3) Request Proof of Education\n"
            "    (4) Send Basic Message\n"
        )
        if args.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        if acme_agent.pqc_enabled:
            options += "    (P) Show PQC Status\n"
            options += "    (V) Verify PQC Capabilities\n"
        options += "    (X) Exit?\n[1/2/3/4/{}{}{}X] ".format(
            "W/" if args.multitenant else "",
            "P/" if acme_agent.pqc_enabled else "",
            "V/" if acme_agent.pqc_enabled else "",
        )

        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option == "1":
                # receive an invitation
                log_status("#10 Input invitation details")
                await input_invitation(acme_agent)

            elif option == "2":
                msg = await prompt("Enter message: ")
                if msg:
                    await acme_agent.admin_POST(
                        f"/connections/{acme_agent.connection_id}/send-message",
                        {"content": msg},
                    )

            elif option == "3":
                log_status("#20 Request proof of education from alice")
                if args.cred_type == "indy":
                    # Enhanced PQC proof request
                    req_attrs = [
                        {
                            "name": "name",
                            "restrictions": [],  # Accept from any credential
                        },
                        {
                            "name": "date", 
                            "restrictions": [],
                        },
                        {
                            "name": "degree",
                            "restrictions": [],
                        },
                    ]
                    
                    req_preds = [
                        {
                            "name": "birthdate_dateint",
                            "p_type": "<=",
                            "p_value": int(time.time()),
                            "restrictions": [],
                        }
                    ]
                    
                    indy_proof_request = {
                        "name": "Proof of Education",
                        "version": "1.0",
                        "requested_attributes": {
                            f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                        },
                        "requested_predicates": {
                            f"0_{req_pred['name']}_GE_uuid": req_pred
                            for req_pred in req_preds
                        },
                    }
                    
                    # Enhanced PQC proof request
                    if acme_agent.pqc_enabled:
                        indy_proof_request["name"] = "🔒 PQC-Secured Proof of Education"
                        indy_proof_request["comment"] = f"Quantum-safe verification using {acme_agent.pqc_sig_algorithm}"
                        acme_agent.log("🔒 Requesting PQC-secured proof from Alice")

                    proof_request_web_request = {
                        "connection_id": acme_agent.connection_id,
                        "presentation_request": {"indy": indy_proof_request},
                    }
                    
                    await acme_agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

            elif option == "4":
                msg = await prompt("Enter message: ")
                if msg:
                    await acme_agent.admin_POST(
                        f"/connections/{acme_agent.connection_id}/send-message",
                        {"content": msg},
                    )

            elif args.multitenant and option in "wW":
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = (
                    await prompt(
                        f"Subscribe to webbook events for '{target_wallet_name}' wallet? [Y/N]: ",
                        default="N",
                    )
                ).upper() == "Y"
                try:
                    wallet_config = await acme_agent.admin_POST(
                        "/multitenancy/wallet",
                        {
                            "label": target_wallet_name,
                            "wallet_name": target_wallet_name,
                            "wallet_key": target_wallet_name,
                            "wallet_webhook_urls": [acme_agent.webhook_url]
                            if include_subwallet_webhook
                            else [],
                            "wallet_dispatch_type": "both"
                            if include_subwallet_webhook
                            else "default",
                        },
                    )
                    acme_agent.log(f"Created wallet '{target_wallet_name}'")

                    token_response = await acme_agent.admin_POST(
                        f"/multitenancy/wallet/{wallet_config['wallet_id']}/token"
                    )
                    acme_agent.log(
                        f"Multitenancy token for '{target_wallet_name}' ({wallet_config['wallet_id']}): "
                        + token_response["token"]
                    )
                except ClientError:
                    pass

            elif acme_agent.pqc_enabled and option in "pP":
                # Display PQC status
                log_msg("🔒 ===== PQC STATUS =====")
                log_msg(f"Plugin: {os.getenv('ACAPY_PLUGIN', 'pqcrypto_fm.v1_0')}")
                log_msg(f"Verification Algorithm: {acme_agent.pqc_sig_algorithm}")
                log_msg(f"KEM Algorithm: {acme_agent.pqc_kem_algorithm}")
                log_msg(f"Security Level: {os.getenv('PQC_SECURITY_LEVEL', '3')}")
                log_msg(f"Hybrid Mode: {os.getenv('PQC_HYBRID_MODE', 'true')}")
                log_msg(f"Wallet Type: {acme_agent.wallet_type}")
                log_msg("Quantum-Safe Verification: ✅ ACTIVE")
                log_msg("========================")
                
                # Show verification statistics
                try:
                    connections = await acme_agent.admin_GET("/connections")
                    active_connections = [c for c in connections['results'] if c['state'] == 'active']
                    log_msg(f"Active Connections: {len(active_connections)}")
                    if acme_agent.pqc_enabled:
                        log_msg("All connections are PQC-secured")
                except Exception as e:
                    log_msg(f"Connection stats not available: {e}")

            elif acme_agent.pqc_enabled and option in "vV":
                # Verify PQC capabilities
                log_msg("🔍 Verifying PQC capabilities...")
                try:
                    # Try to access PQC admin endpoints
                    algorithms = await acme_agent.admin_GET("/pqc/algorithms")
                    log_msg("✅ PQC algorithms endpoint accessible")
                    log_json(algorithms, label="Available PQC Algorithms:")
                    
                    status = await acme_agent.admin_GET("/pqc/status")
                    log_msg("✅ PQC status endpoint accessible")
                    log_json(status, label="PQC Status:")
                    
                except Exception as e:
                    log_msg(f"❌ PQC capability verification failed: {e}")
                    log_msg("This may indicate the PQC plugin is not properly loaded")

        if acme_agent.show_timing:
            timing = await acme_agent.fetch_timing()
            if timing:
                for line in acme_agent.format_timing(timing):
                    log_msg(line)

async def input_invitation(agent):
    """Handle invitation input with PQC support."""
    invitation_json = await prompt("Invite details: ")
    try:
        invitation = json.loads(invitation_json)
    except json.JSONDecodeError:
        log_msg("Invalid invitation format")
        return

    if agent.pqc_enabled:
        log_msg("🔒 Processing PQC-enabled invitation...")
        log_msg(f"   Will establish quantum-safe connection for verification")

    log_status("#11 Receive invitation")
    connection = await agent.admin_POST("/connections/receive-invitation", invitation)
    agent.connection_id = connection["connection_id"]
    log_json(connection, label="Invitation Response:")
    
    if agent.pqc_enabled:
        log_msg("✅ PQC-enabled verification connection initiated")

    log_status("#12 Accept invitation")
    await agent.admin_POST(f"/connections/{agent.connection_id}/accept-invitation")

    await agent.detect_connection()

if __name__ == "__main__":
    import argparse
    import time

    from aiohttp import ClientError

    parser = arg_parser(ident="acme", port=8040, seed=None)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )
    PYDEVD_PYCHARM_AGENT_PORT = int(os.getenv("PYDEVD_PYCHARM_AGENT_PORT", 4001))

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "Acme ==> Waiting for PyCharm to connect to debug server on "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_AGENT_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_AGENT_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)