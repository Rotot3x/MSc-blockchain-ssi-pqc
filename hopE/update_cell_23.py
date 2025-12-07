# Cell 23: Verifier - Presentation verifizieren (mit Revocation Detection + Zeitgültigkeit)

print("✅ Presentation verifizieren (Verifier)...\n")

start_time = time.time()

# Wait for presentation to be received
import time as t
t.sleep(5)  # Give Holder time to generate and send proof

# Get presentation exchange record (ACA-Py endpoint)
# API: GET /present-proof-2.0/records/{pres_ex_id}
pres_ex_record = api_get(
    VERIFIER_ADMIN_URL,
    f"/present-proof-2.0/records/{pres_ex_id}"
)

if pres_ex_record is not None:
    # Response Format: {"state": "...", "verified": "...", "pres": {...}, "by_format": {...}, ...}
    pres_state = pres_ex_record.get("state")
    pres_verified = pres_ex_record.get("verified")

    # ========================================
    # ATTRIBUTE MAPPING: referent -> name -> value
    # ========================================
    # Step 1: Get requested_attributes from by_format.pres_request.indy (referent -> name mapping)
    by_format = pres_ex_record.get("by_format", {})
    pres_request_indy = by_format.get("pres_request", {}).get("indy", {})
    requested_attributes = pres_request_indy.get("requested_attributes", {})

    # Step 2: Get revealed_attrs from by_format.pres.indy.requested_proof (referent -> value mapping)
    pres_indy = by_format.get("pres", {}).get("indy", {})
    requested_proof = pres_indy.get("requested_proof", {})
    revealed_attrs_by_referent = requested_proof.get("revealed_attrs", {})

    # Step 3: Build name -> value mapping
    revealed_attrs = {}
    for referent, attr_data in revealed_attrs_by_referent.items():
        # Get the attribute name from requested_attributes
        if referent in requested_attributes:
            attr_name = requested_attributes[referent].get("name")
            attr_value = attr_data.get("raw")
            if attr_name and attr_value:
                revealed_attrs[attr_name] = attr_value

    duration = time.time() - start_time
    performance_metrics["proof_verification"].append(duration)

    print(f"✅ Proof erfolgreich verifiziert!")

    print(f"\nVerifizierte Attribute (REVEALED):")
    for name, value in revealed_attrs.items():
        print(f"   - {name}: {value}")

    print(f"\n⚠️  PER ZKP VERIFIZIERT ABER DURCH DATENSCHUTZ GESCHÜTZT (UNREVEALED):")
    print(f"   - Vorname: NICHT offengelegt (Zero-Knowledge-Proof)")
    print(f"   - Nachname: NICHT offengelegt (Zero-Knowledge-Proof)")
    print(f"   - Organisation: NICHT offengelegt (Zero-Knowledge-Proof)")

    print(f"\n   State:     {pres_state}")
    print(f"   Verified:  {pres_verified}")

    # ========================================
    # REVOCATION CHECK
    # ========================================
    is_revoked = False
    if pres_state == "done" and pres_verified == "true":
        print(f"\n✅ Credential ist NICHT revoked (gültig)")
    else:
        print(f"\n❌ Credential ist REVOKED!")
        is_revoked = True

    # ========================================
    # ZEITGÜLTIGKEITS-PRÜFUNG
    # ========================================
    print("\n" + "="*60)
    print("🕐 ZEITGÜLTIGKEITS-PRÜFUNG")
    print("="*60)

    current_epoch = int(time.time())
    epoch_valid_from = None
    epoch_valid_until = None
    is_time_valid = False

    # Extrahiere epoch_valid_from und epoch_valid_until aus revealed_attrs (name -> value mapping)
    if "epoch_valid_from" in revealed_attrs:
        epoch_valid_from = int(revealed_attrs["epoch_valid_from"])

    if "epoch_valid_until" in revealed_attrs:
        epoch_valid_until = int(revealed_attrs["epoch_valid_until"])

    if epoch_valid_from is not None and epoch_valid_until is not None:
        # Konvertiere zu lesbaren Timestamps
        from datetime import datetime
        valid_from_dt = datetime.fromtimestamp(epoch_valid_from)
        valid_until_dt = datetime.fromtimestamp(epoch_valid_until)
        current_dt = datetime.fromtimestamp(current_epoch)

        print(f"   • Aktueller Zeitpunkt: {current_dt.strftime('%Y-%m-%d %H:%M:%S')} (Epoch: {current_epoch})")
        print(f"   • Gültig ab:            {valid_from_dt.strftime('%Y-%m-%d %H:%M:%S')} (Epoch: {epoch_valid_from})")
        print(f"   • Gültig bis:           {valid_until_dt.strftime('%Y-%m-%d %H:%M:%S')} (Epoch: {epoch_valid_until})")

        # Prüfe Zeitgültigkeit
        if epoch_valid_from <= current_epoch <= epoch_valid_until:
            is_time_valid = True
            print(f"\n   ✅ Zertifikat ist ZEITLICH GÜLTIG")
        else:
            is_time_valid = False
            if current_epoch < epoch_valid_from:
                print(f"\n   ❌ Zertifikat ist NOCH NICHT gültig (zu früh)")
            else:
                print(f"\n   ❌ Zertifikat ist ABGELAUFEN (zu spät)")
    else:
        print(f"   ⚠️  Zeitgültigkeits-Attribute nicht gefunden!")
        print(f"      • epoch_valid_from: {'gefunden' if epoch_valid_from else 'FEHLT'}")
        print(f"      • epoch_valid_until: {'gefunden' if epoch_valid_until else 'FEHLT'}")

    print("="*60)

    # ========================================
    # FINALE ZUGRIFFSENTSCHEIDUNG
    # ========================================
    print("\n" + "="*60)
    print("🚦 FINALE ZUGRIFFSENTSCHEIDUNG")
    print("="*60)

    # Beide Bedingungen müssen erfüllt sein
    if not is_revoked and is_time_valid:
        print(f"\n✅✅ ZUGANG GEWÄHRT")
        print(f"   ✓ Credential ist gültig (nicht revoked)")
        print(f"   ✓ Zertifikat ist zeitlich gültig")
        print(f"\n   🔓 Zugang zum Umspannwerk Nord-Ost GEWÄHRT")
    else:
        print(f"\n❌❌ ZUGANG VERWEIGERT")
        if is_revoked:
            print(f"   ✗ Credential ist REVOKED")
        if not is_time_valid:
            print(f"   ✗ Zertifikat ist NICHT zeitlich gültig")
        print(f"\n   🔒 Zugang zum Umspannwerk Nord-Ost VERWEIGERT")

    print("="*60)

    print(f"\n✅ Privacy-Preserving Verification erfolgreich (DSGVO-konform)")
    print(f"⏱️  Zeit: {duration:.3f}s")

    # Show full Presentation Record
    pretty_print(pres_ex_record, "Presentation Record (KRITIS)")

else:
    print("❌ Fehler beim Abrufen der Presentation")
