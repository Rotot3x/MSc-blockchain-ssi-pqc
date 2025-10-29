#!/usr/bin/env python3
"""Test to see how did-peer-4 library numbers keys in the DID Document."""

from did_peer_4 import encode, decode
from did_peer_4.input_doc import input_doc_from_keys_and_services, KeySpec
import json

# Create two dummy multikeys (we just need the format, not real crypto)
sig_multikey = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"  # Ed25519 example
kem_multikey = "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"  # X25519 example

# Create KeySpecs in same order as our PQC code
key_specs = [
    KeySpec(
        multikey=sig_multikey,
        relationships=["authentication", "assertionMethod"]
    ),
    KeySpec(
        multikey=kem_multikey,
        relationships=["keyAgreement"]
    ),
]

# Create a service that references key-2 (like our current code)
services = [{
    "id": "#didcomm-0",
    "type": "did-communication",
    "recipientKeys": ["#key-2"],  # What we currently have
    "routingKeys": [],
    "serviceEndpoint": "https://example.com",
    "priority": 0,
}]

# Generate the DID
input_doc = input_doc_from_keys_and_services(
    keys=key_specs,
    services=services
)
did = encode(input_doc)

print("=" * 80)
print("Generated did:peer:4:")
print(f"  {did[:100]}...")
print()

# Decode it to see the DID Document
did_doc = decode(did)

print("DID Document:")
print(json.dumps(did_doc, indent=2))
print()

print("=" * 80)
print("Key IDs in DID Document:")
if "verificationMethod" in did_doc:
    for vm in did_doc["verificationMethod"]:
        print(f"  - {vm['id']}")
print()

print("Service references:")
if "service" in did_doc:
    for svc in did_doc["service"]:
        print(f"  Service {svc['id']}:")
        print(f"    recipientKeys: {svc.get('recipientKeys', [])}")
print()
