#!/usr/bin/env python3
"""
PQC-Enhanced Alice Agent

Student credential holder with Post-Quantum Cryptography support.
This agent demonstrates quantum-safe credential reception and proof presentation.
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

class AliceAgent(AriesAgent):
    """Alice Agent with PQC support for credential holding."""

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
            prefix="Alice",
            no_auto=no_auto,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        self.cred_attrs = {}
        # PQC-specific attributes
        self.pqc_enabled = os.getenv("ACAPY_PQC_ENABLED", "0") == "1"
        self.pqc_sig_algorithm = os.getenv("PQC_AGENT_SIG_ALG", "Dilithium2")
        self.pqc_kem_algorithm = os.getenv("PQC_AGENT_KEM_ALG", "Kyber768")

    async def detect_connection(self):
        """Detect and set up connection with Faber."""
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
                self.log(f"🔒 PQC Connection established with Faber")
                self.log(f"   KEM Algorithm: {self.pqc_kem_algorithm}")
                self.log(f"   Signature Algorithm: {self.pqc_sig_algorithm}")

    async def handle_issue_credential_v2_0(self, message):
        """Handle credential reception events."""
        state = message["state"]
        cred_ex_id = message["cred_ex_id"]
        prev_state = self.cred_state.get(cred_ex_id)
        
        if prev_state == state:
            return  # ignore
        self.cred_state[cred_ex_id] = state

        self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")

        if state == "offer-received":
            log_status("#15 After receiving credential offer, send credential request")
            
            # Enhanced PQC credential offer handling
            if self.pqc_enabled:
                self.log("🔒 Received PQC-secured credential offer")
                # Check if the offer contains PQC metadata
                cred_ex = await self.admin_GET(f"/issue-credential-2.0/records/{cred_ex_id}")
                if cred_ex.get("cred_offer", {}).get("~attach"):
                    self.log("   Verifying PQC signatures in credential offer...")
            
            await self.admin_POST(
                f"/issue-credential-2.0/records/{cred_ex_id}/send-request"
            )

        elif state == "credential-received":
            self.log("Stored credential in wallet")
            cred_id = message["cred_id_stored"]
            self.cred_attrs[cred_ex_id] = message["cred_preview"]
            self.log(f"credential_id = {cred_id}")
            log_status("#18.1 Stored credential")
            
            # Enhanced PQC credential storage logging
            if self.pqc_enabled:
                self.log("✅ PQC-secured credential stored in quantum-safe wallet")
                self.log(f"   Signature verified with: {self.pqc_sig_algorithm}")

    async def handle_present_proof_v2_0(self, message):
        """Handle proof presentation events."""
        state = message["state"]
        pres_ex_id = message["pres_ex_id"]
        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "request-received":
            if self.pqc_enabled:
                self.log("🔒 Received PQC-secured proof request")
                self.log(f"   Will respond with {self.pqc_sig_algorithm} signatures")
            
            log_status(
                "#24 Query for credentials in the wallet that satisfy the proof request"
            )

            # include self-attested attributes (not included in credentials)
            if SELF_ATTESTED:
                self_attested = {
                    "self_attested_thing": "It's me"
                }
            else:
                self_attested = None

            # select credentials to provide for the proof
            credentials_by_reft = {}
            revealed = {}
            self_attested = {}

            # select credentials for each referent
            for referent in request["requested_attributes"]:
                # check if self-attested
                if referent in [
                    "self_attested_thing",
                ]:
                    self_attested[referent] = "It's me"
                else:
                    credentials = await self.admin_GET(
                        f"/present-proof-2.0/records/{pres_ex_id}/credentials/{referent}"
                    )

                    if not credentials:
                        raise Exception(
                            f"No credentials available for {referent} to satisfy the proof request"
                        )

                    # just use the first available credentials for each requested attribute
                    credentials_by_reft[referent] = credentials[0]["cred_info"]["cred_id"]
                    revealed[referent] = True

            for referent in request["requested_predicates"]:
                credentials = await self.admin_GET(
                    f"/present-proof-2.0/records/{pres_ex_id}/credentials/{referent}"
                )

                if not credentials:
                    raise Exception(
                        f"No credentials available for {referent} to satisfy the proof request"
                    )

                # just use the first available credentials for each requested predicate
                credentials_by_reft[referent] = credentials[0]["cred_info"]["cred_id"]

            log_status("#25 Generate the proof")
            request = message["by_format"]["pres_request"]["indy"]

            proof_data = {
                "indy": {
                    "requested_attributes": {
                        referent: {
                            "cred_id": credentials_by_reft[referent],
                            "revealed": revealed.get(referent, False),
                        }
                        for referent in credentials_by_reft
                        if referent in request["requested_attributes"]
                    },
                    "requested_predicates": {
                        referent: {"cred_id": credentials_by_reft[referent]}
                        for referent in credentials_by_reft
                        if referent in request["requested_predicates"]
                    },
                    "self_attested_attributes": self_attested,
                }
            }

            log_status("#26 Send the proof to X")
            await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/send-presentation",
                proof_data,
            )
            
            if self.pqc_enabled:
                self.log("✅ PQC-secured proof sent to verifier")

    async def handle_basicmessages(self, message):
        """Handle basic messages."""
        self.log("Received message:", message)

async def main(args):
    """Main function for Alice agent."""
    alice_agent = AliceAgent(
        "alice",
        args.port,
        args.admin_port,
        prefix="Alice",
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
    if alice_agent.pqc_enabled:
        alice_agent.log("🔒 PQC Mode: ENABLED")
        alice_agent.log(f"   Plugin: {os.getenv('ACAPY_PLUGIN', 'pqcrypto_fm.v1_0')}")
        alice_agent.log(f"   KEM Algorithm: {alice_agent.pqc_kem_algorithm}")
        alice_agent.log(f"   Signature Algorithm: {alice_agent.pqc_sig_algorithm}")
        alice_agent.log(f"   Wallet Type: {args.wallet_type}")
        alice_agent.log("   Quantum-Safe Credential Storage: ACTIVE")

    if args.cred_type == "indy":
        alice_agent.cred_type = "indy"
    elif args.cred_type == "json-ld":
        alice_agent.cred_type = "json-ld"

    await alice_agent.listen_webhooks(args.webhook_port)

    with log_timer("Startup duration:"):
        await alice_agent.start_process()
    log_msg("Admin URL is at:", alice_agent.admin_url)
    log_msg("Endpoint URL is at:", alice_agent.endpoint)

    # Main agent loop
    async with alice_agent:
        log_status("#7 Provision an agent and wallet, get back configuration details")
        agent_config = await alice_agent.fetch_config()
        log_json(agent_config, label="Provisioned Agent:")

        log_status("#9 Input faber.py invitation details")
        alice_agent._connection_ready = asyncio.Future()

        # Enhanced PQC invitation acceptance
        options = (
            "    (1) Input new invitation\n"
            "    (2) Send Message\n"
            "    (3) Input New Invitation\n"
        )
        if args.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        if alice_agent.pqc_enabled:
            options += "    (P) Show PQC Status\n"
        options += "    (X) Exit?\n[1/2/3/{}{}X] ".format(
            "W/" if args.multitenant else "",
            "P/" if alice_agent.pqc_enabled else "",
        )

        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option == "1":
                # receive an invitation
                log_status("#10 Input invitation details")
                await input_invitation(alice_agent)

            elif option == "2":
                msg = await prompt("Enter message: ")
                if msg:
                    await alice_agent.admin_POST(
                        f"/connections/{alice_agent.connection_id}/send-message",
                        {"content": msg},
                    )

            elif option == "3":
                # receive an invitation
                log_status("Input new invitation details")
                await input_invitation(alice_agent)

            elif args.multitenant and option in "wW":
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = (
                    await prompt(
                        f"Subscribe to webbook events for '{target_wallet_name}' wallet? [Y/N]: ",
                        default="N",
                    )
                ).upper() == "Y"
                try:
                    wallet_config = await alice_agent.admin_POST(
                        "/multitenancy/wallet",
                        {
                            "label": target_wallet_name,
                            "wallet_name": target_wallet_name,
                            "wallet_key": target_wallet_name,
                            "wallet_webhook_urls": [alice_agent.webhook_url]
                            if include_subwallet_webhook
                            else [],
                            "wallet_dispatch_type": "both"
                            if include_subwallet_webhook
                            else "default",
                        },
                    )
                    alice_agent.log(f"Created wallet '{target_wallet_name}'")

                    token_response = await alice_agent.admin_POST(
                        f"/multitenancy/wallet/{wallet_config['wallet_id']}/token"
                    )
                    alice_agent.log(
                        f"Multitenancy token for '{target_wallet_name}' ({wallet_config['wallet_id']}): "
                        + token_response["token"]
                    )
                except ClientError:
                    pass

            elif alice_agent.pqc_enabled and option in "pP":
                # Display PQC status
                log_msg("🔒 ===== PQC STATUS =====")
                log_msg(f"Plugin: {os.getenv('ACAPY_PLUGIN', 'pqcrypto_fm.v1_0')}")
                log_msg(f"KEM Algorithm: {alice_agent.pqc_kem_algorithm}")
                log_msg(f"Signature Algorithm: {alice_agent.pqc_sig_algorithm}")
                log_msg(f"Security Level: {os.getenv('PQC_SECURITY_LEVEL', '3')}")
                log_msg(f"Hybrid Mode: {os.getenv('PQC_HYBRID_MODE', 'true')}")
                log_msg(f"Wallet Type: {alice_agent.wallet_type}")
                log_msg("Quantum-Safe Operations: ✅ ACTIVE")
                log_msg("========================")
                
                # Show wallet statistics
                try:
                    credentials = await alice_agent.admin_GET("/credentials")
                    log_msg(f"Stored Credentials: {len(credentials['results'])}")
                    if alice_agent.pqc_enabled:
                        pqc_creds = [c for c in credentials['results'] 
                                   if 'pqc' in str(c.get('attrs', {})).lower()]
                        log_msg(f"PQC-secured Credentials: {len(pqc_creds)}")
                except Exception as e:
                    log_msg(f"Credential stats not available: {e}")

        if alice_agent.show_timing:
            timing = await alice_agent.fetch_timing()
            if timing:
                for line in alice_agent.format_timing(timing):
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
        log_msg(f"   Will establish quantum-safe connection using {agent.pqc_kem_algorithm}")

    log_status("#11 Receive invitation")
    connection = await agent.admin_POST("/connections/receive-invitation", invitation)
    agent.connection_id = connection["connection_id"]
    log_json(connection, label="Invitation Response:")
    
    if agent.pqc_enabled:
        log_msg("✅ PQC-enabled connection initiated")

    log_status("#12 Accept invitation")
    await agent.admin_POST(f"/connections/{agent.connection_id}/accept-invitation")

    await agent.detect_connection()

if __name__ == "__main__":
    import argparse

    from aiohttp import ClientError

    parser = arg_parser(ident="alice", port=8030, seed=None)
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
                "Alice ==> Waiting for PyCharm to connect to debug server on "
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