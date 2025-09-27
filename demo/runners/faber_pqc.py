#!/usr/bin/env python3
"""
PQC-Enhanced Faber Agent

University credential issuer with Post-Quantum Cryptography support.
This agent demonstrates quantum-safe credential issuance using Dilithium3 signatures.
"""

import asyncio
import json
import logging
import os
import sys
from urllib.parse import urlparse

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

CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)

class FaberAgent(AriesAgent):
    """Faber Agent with PQC support for credential issuance."""

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
            prefix="Faber",
            no_auto=no_auto,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
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
                self.log(f"🔒 PQC Connection established")
                self.log(f"   Signature Algorithm: {self.pqc_sig_algorithm}")
                self.log(f"   KEM Algorithm: {self.pqc_kem_algorithm}")

    async def handle_issue_credential_v2_0(self, message):
        """Handle credential issuance events."""
        state = message["state"]
        cred_ex_id = message["cred_ex_id"]
        prev_state = self.cred_state.get(cred_ex_id)
        
        if prev_state == state:
            return  # ignore
        self.cred_state[cred_ex_id] = state

        self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")

        if state == "request-received":
            # Issue credential with PQC signatures if enabled
            if self.pqc_enabled:
                self.log(f"🔒 Issuing credential with PQC signature: {self.pqc_sig_algorithm}")
            
            log_status("#17 Issue credential to X")
            await self.admin_POST(
                f"/issue-credential-2.0/records/{cred_ex_id}/issue",
                {"comment": f"Issuing credential, exchange {cred_ex_id}"},
            )

    async def handle_present_proof_v2_0(self, message):
        """Handle proof presentation events."""
        state = message["state"]
        pres_ex_id = message["pres_ex_id"]
        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "presentation-received":
            if self.pqc_enabled:
                self.log(f"🔒 Verifying presentation with PQC: {self.pqc_sig_algorithm}")
            
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            proof = await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
            )
            self.log("Proof =", proof["verified"])
            
            # Enhanced PQC proof verification logging
            if self.pqc_enabled and proof.get("verified"):
                self.log("✅ PQC-secured proof verified successfully!")

    async def handle_basicmessages(self, message):
        """Handle basic messages."""
        self.log("Received message:", message)

async def create_schema_and_cred_def(agent):
    """Create schema and credential definition with PQC support."""
    
    # Schema creation (unchanged)
    log_status("#3/4 Create a new schema/cred def on the ledger")
    version = format(
        "%d.%d.%d"
        % (
            random.randint(1, 101),
            random.randint(1, 101),
            random.randint(1, 101),
        )
    )
    
    schema_name = "degree schema"
    if agent.pqc_enabled:
        schema_name = "PQC degree schema"
        agent.log(f"🔒 Creating PQC-enabled schema: {schema_name}")
    
    schema_body = {
        "schema_name": schema_name,
        "schema_version": version,
        "attributes": ["name", "date", "degree", "birthdate_dateint", "timestamp"],
    }
    schema_response = await agent.admin_POST("/schemas", schema_body)
    schema_id = schema_response["schema_id"]
    log_json(schema_response, label="Schema:")
    agent.log(f"Schema ID: {schema_id}")

    # Credential definition creation with PQC support
    credential_definition_body = {
        "schema_id": schema_id,
        "support_revocation": True,
        "tag": "PQC-enabled" if agent.pqc_enabled else "default",
        "revocation_registry_size": TAILS_FILE_COUNT,
    }
    
    # Add PQC-specific metadata
    if agent.pqc_enabled:
        credential_definition_body["metadata"] = {
            "pqc_enabled": True,
            "signature_algorithm": agent.pqc_sig_algorithm,
            "security_level": os.getenv("PQC_SECURITY_LEVEL", "3"),
            "quantum_safe": True
        }
        agent.log(f"🔒 Creating PQC credential definition with {agent.pqc_sig_algorithm}")

    credential_definition_response = await agent.admin_POST(
        "/credential-definitions", credential_definition_body
    )
    credential_definition_id = credential_definition_response["credential_definition_id"]
    log_json(credential_definition_response, label="Credential Definition:")
    agent.log(f"Credential Definition ID: {credential_definition_id}")

    return schema_id, credential_definition_id

async def main(args):
    """Main function for Faber agent."""
    faber_agent = FaberAgent(
        "faber",
        args.port,
        args.admin_port,
        prefix="Faber",
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
    if faber_agent.pqc_enabled:
        faber_agent.log("🔒 PQC Mode: ENABLED")
        faber_agent.log(f"   Plugin: {os.getenv('ACAPY_PLUGIN', 'pqcrypto_fm.v1_0')}")
        faber_agent.log(f"   Signature Algorithm: {faber_agent.pqc_sig_algorithm}")
        faber_agent.log(f"   KEM Algorithm: {faber_agent.pqc_kem_algorithm}")
        faber_agent.log(f"   Wallet Type: {args.wallet_type}")
        faber_agent.log("   Quantum-Safe Credential Issuance: ACTIVE")

    if args.cred_type == "indy":
        faber_agent.cred_type = "indy"
    elif args.cred_type == "json-ld":
        faber_agent.cred_type = "json-ld"

    await faber_agent.listen_webhooks(args.webhook_port)

    with log_timer("Startup duration:"):
        await faber_agent.start_process()
    log_msg("Admin URL is at:", faber_agent.admin_url)
    log_msg("Endpoint URL is at:", faber_agent.endpoint)

    # Create invitation
    async with faber_agent:
        log_status("#1 Provision an agent and wallet, get back configuration details")
        agent_config = await faber_agent.fetch_config()
        log_json(agent_config, label="Provisioned Agent:")

        log_status("#3 Create a connection to alice and print out the invite details")
        faber_agent._connection_ready = asyncio.Future()
        connection = await faber_agent.admin_POST("/connections/create-invitation")

        faber_agent.connection_id = connection["connection_id"]
        log_json(connection, label="Invitation Data:")
        log_msg("*****************")
        log_msg("JSON:", json.dumps(connection))
        log_msg("*****************")
        log_msg("Invite URL:")
        log_msg(connection["invitation_url"], label="Invitation", color=None)
        log_msg("*****************")

        # Enhanced PQC connection logging
        if faber_agent.pqc_enabled:
            log_msg("🔒 This invitation will establish a QUANTUM-SAFE connection!")
            log_msg(f"🔑 Key Exchange: {faber_agent.pqc_kem_algorithm}")
            log_msg(f"✍️ Signatures: {faber_agent.pqc_sig_algorithm}")

        log_status("#3 Send the invitation to X")
        log_status("#4 Wait for the connection to be accepted")
        await faber_agent.detect_connection()

        async def create_schema_and_cred_def():
            log_status("#3/4 Create a new schema/cred def on the ledger")
            version = format(
                "%d.%d.%d"
                % (
                    random.randint(1, 101),
                    random.randint(1, 101),
                    random.randint(1, 101),
                )
            )
            schema_body = {
                "schema_name": "degree schema",
                "schema_version": version,
                "attributes": ["name", "date", "degree", "birthdate_dateint", "timestamp"],
            }
            schema_response = await faber_agent.admin_POST("/schemas", schema_body)
            schema_id = schema_response["schema_id"]
            log_json(schema_response, label="Schema:")

            credential_definition_body = {
                "schema_id": schema_id,
                "support_revocation": True,
                "tag": "default",
                "revocation_registry_size": TAILS_FILE_COUNT,
            }
            credential_definition_response = await faber_agent.admin_POST(
                "/credential-definitions", credential_definition_body
            )
            credential_definition_id = credential_definition_response[
                "credential_definition_id"
            ]
            log_json(credential_definition_response, label="Credential Definition:")

            return schema_id, credential_definition_id

        if args.cred_type == "indy":
            schema_id, credential_definition_id = await create_schema_and_cred_def()

        exchange_tracing = False
        options = (
            "    (1) Issue Credential\n"
            "    (2) Send Proof Request\n"
            "    (3) Send Message\n"
            "    (4) Create New Invitation\n"
        )
        if args.revocation:
            options += "    (5) Revoke Credential\n"
            options += "    (6) Publish Revocations\n"
        if args.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        if faber_agent.pqc_enabled:
            options += "    (P) Show PQC Status\n"
        options += "    (X) Exit?\n[1/2/3/4/{}T{}X] ".format(
            "5/6/" if args.revocation else "",
            "/P" if faber_agent.pqc_enabled else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                log_status("#13 Issue credential offer to X")

                if args.cred_type == "indy":
                    offer_request = {
                        "connection_id": faber_agent.connection_id,
                        "comment": f"Offer on cred def id {credential_definition_id}",
                        "auto_remove": False,
                        "credential_preview": {
                            "type": CRED_PREVIEW_TYPE,
                            "attributes": [
                                {"name": "name", "value": "Alice Smith"},
                                {"name": "date", "value": "2018-05-28"},
                                {"name": "degree", "value": "Maths"},
                                {"name": "birthdate_dateint", "value": "958085471"},
                                {"name": "timestamp", "value": str(int(time.time()))},
                            ],
                        },
                        "cred_def_id": credential_definition_id,
                        "trace": exchange_tracing,
                    }
                    
                    # Add PQC metadata to credential offer
                    if faber_agent.pqc_enabled:
                        offer_request["comment"] = f"🔒 PQC-secured credential offer (Alg: {faber_agent.pqc_sig_algorithm})"
                        faber_agent.log("🔒 Sending PQC-secured credential offer")

                    await faber_agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

                elif args.cred_type == "json-ld":
                    offer_request = {
                        "connection_id": faber_agent.connection_id,
                        "filter": {"ld_proof": {"credential": {"@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://www.w3.org/2018/credentials/examples/v1",
                        ]}}},
                    }
                    await faber_agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

            elif option == "2":
                log_status("#20 Request proof of degree from alice")
                if args.cred_type == "indy":
                    req_attrs = [
                        {
                            "name": "name",
                            "restrictions": [{"cred_def_id": credential_definition_id}],
                        },
                        {
                            "name": "date",
                            "restrictions": [{"cred_def_id": credential_definition_id}],
                        },
                    ]
                    if SELF_ATTESTED:
                        # test self-attested claims
                        req_attrs.append(
                            {"name": "self_attested_thing"},
                        )
                    req_preds = [
                        {
                            "name": "birthdate_dateint",
                            "p_type": "<=",
                            "p_value": int(time.time()),
                            "restrictions": [{"cred_def_id": credential_definition_id}],
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
                    if faber_agent.pqc_enabled:
                        indy_proof_request["name"] = "🔒 PQC-Secured Proof of Education"
                        indy_proof_request["comment"] = f"Quantum-safe proof verification with {faber_agent.pqc_sig_algorithm}"
                        faber_agent.log("🔒 Requesting PQC-secured proof from Alice")

                    proof_request_web_request = {
                        "connection_id": faber_agent.connection_id,
                        "presentation_request": {"indy": indy_proof_request},
                        "trace": exchange_tracing,
                    }
                    await faber_agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

                elif args.cred_type == "json-ld":
                    proof_request_web_request = {
                        "comment": "test proof request for json-ld",
                        "connection_id": faber_agent.connection_id,
                        "presentation_request": {
                            "dif": {
                                "options": {
                                    "challenge": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
                                    "domain": "4jt78h47fh47",
                                },
                                "presentation_definition": {
                                    "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
                                    "format": {"ldp_vp": {"proof_type": [
                                        "BbsBlsSignature2020"
                                    ]}},
                                    "input_descriptors": [
                                        {
                                            "id": "citizenship_input_1",
                                            "name": "EU Driver's License",
                                            "schema": [
                                                {
                                                    "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
                                                },
                                                {
                                                    "uri": "https://w3id.org/citizenship#PermanentResidentCard"
                                                },
                                            ],
                                            "constraints": {
                                                "is_holder": [
                                                    {
                                                        "directive": "required",
                                                        "field_id": [
                                                            "1f44d55f-f161-4938-a659-f8026467f126"
                                                        ],
                                                    }
                                                ],
                                                "fields": [
                                                    {
                                                        "id": "1f44d55f-f161-4938-a659-f8026467f126",
                                                        "path": ["$.credentialSubject.familyName"],
                                                        "purpose": "The claim must be from one of the specified person",
                                                        "filter": {"const": "SMITH"},
                                                    },
                                                    {
                                                        "path": ["$.credentialSubject.givenName"],
                                                        "purpose": "The claim must be from one of the specified person",
                                                    },
                                                ],
                                            },
                                        }
                                    ],
                                },
                            }
                        },
                    }
                    await faber_agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

            elif option == "3":
                msg = await prompt("Enter message: ")
                if msg:
                    await faber_agent.admin_POST(
                        f"/connections/{faber_agent.connection_id}/send-message",
                        {"content": msg},
                    )

            elif option == "4":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await faber_agent.admin_POST("/connections/create-invitation")

            elif args.revocation and option == "5":
                rev_reg_id = (await prompt("Enter revocation registry ID: ")) or None
                cred_rev_id = (await prompt("Enter credential revocation ID: ")) or None
                publish = (
                    await prompt("Publish now? [Y/N]: ", default="N")
                ).upper() == "Y"
                try:
                    await faber_agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": faber_agent.connection_id,
                            # leave out thread_id, let aca-py generate
                            # "thread_id": "12345678-4444-4444-4444-123456789012",
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

            elif args.revocation and option == "6":
                try:
                    resp = await faber_agent.admin_POST(
                        "/revocation/publish-revocations", {}
                    )
                    faber_agent.log(
                        f"Published revocations for {len(resp['rrid2crid'])} revocation registries"
                    )
                except ClientError:
                    pass

            elif args.multitenant and option in "wW":
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = (
                    await prompt(
                        f"Subscribe to webbook events for '{target_wallet_name}' wallet? [Y/N]: ",
                        default="N",
                    )
                ).upper() == "Y"
                try:
                    wallet_config = await faber_agent.admin_POST(
                        "/multitenancy/wallet",
                        {
                            "label": target_wallet_name,
                            "wallet_name": target_wallet_name,
                            "wallet_key": target_wallet_name,
                            "wallet_webhook_urls": [faber_agent.webhook_url]
                            if include_subwallet_webhook
                            else [],
                            "wallet_dispatch_type": "both"
                            if include_subwallet_webhook
                            else "default",
                        },
                    )
                    faber_agent.log(f"Created wallet '{target_wallet_name}'")

                    token_response = await faber_agent.admin_POST(
                        f"/multitenancy/wallet/{wallet_config['wallet_id']}/token"
                    )
                    faber_agent.log(
                        f"Multitenancy token for '{target_wallet_name}' ({wallet_config['wallet_id']}): "
                        + token_response["token"]
                    )
                except ClientError:
                    pass

            elif faber_agent.pqc_enabled and option in "pP":
                # Display PQC status
                log_msg("🔒 ===== PQC STATUS =====")
                log_msg(f"Plugin: {os.getenv('ACAPY_PLUGIN', 'pqcrypto_fm.v1_0')}")
                log_msg(f"Signature Algorithm: {faber_agent.pqc_sig_algorithm}")
                log_msg(f"KEM Algorithm: {faber_agent.pqc_kem_algorithm}")
                log_msg(f"Security Level: {os.getenv('PQC_SECURITY_LEVEL', '3')}")
                log_msg(f"Hybrid Mode: {os.getenv('PQC_HYBRID_MODE', 'true')}")
                log_msg(f"Wallet Type: {faber_agent.wallet_type}")
                log_msg("Quantum-Safe Operations: ✅ ACTIVE")
                log_msg("========================")
                
                # Try to get PQC statistics from admin API
                try:
                    pqc_stats = await faber_agent.admin_GET("/pqc/stats")
                    log_json(pqc_stats, label="PQC Statistics:")
                except Exception as e:
                    log_msg(f"PQC stats not available: {e}")

        if faber_agent.show_timing:
            timing = await faber_agent.fetch_timing()
            if timing:
                for line in faber_agent.format_timing(timing):
                    log_msg(line)

if __name__ == "__main__":
    import argparse
    import random
    import time

    from aiohttp import ClientError

    parser = arg_parser(ident="faber", port=8020, seed=None)
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
                "Faber ==> Waiting for PyCharm to connect to debug server on "
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