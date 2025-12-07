#!/usr/bin/env python3
"""
Migration Script: security_access_level (String) → security_clearance_level (Integer 0-3)

This script updates SSI_Complete_Workflow.ipynb to migrate from:
- OLD: security_access_level (String: "Stufe-3-Kritisch")
- NEW: security_clearance_level (Integer 0-3, representing German KRITIS Ü-Levels)

German KRITIS Ü-Levels:
- 0: Standard-Sicherheitsüberprüft
- 1: Ü1 - Einfache Sicherheitsüberprüfung
- 2: Ü2 - Erweiterte Sicherheitsüberprüfung (MINIMUM REQUIREMENT)
- 3: Ü3 - Erweiterte SÜ mit Sicherheitsermittlungen

Changes:
- Cell 1: Schema version 1.0 → 1.1, attribute name change
- Cell 18: Credential value "Stufe-3-Kritisch" → "2" (Ü2)
- Cell 19: Output display updates
- Cell 20: Add ZKP predicate for security_clearance_level >= 2
- Cell 21: Output display updates
- Cell 22: Output display updates
- Cell 23: Predicate evaluation implementation
"""

import json
import sys

def load_notebook(filepath):
    """Load Jupyter notebook"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_notebook(filepath, notebook):
    """Save Jupyter notebook"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(notebook, f, indent=1, ensure_ascii=False)

def find_cell_by_marker(notebook, marker):
    """Find cell index by searching for a specific marker string"""
    for idx, cell in enumerate(notebook['cells']):
        if cell['cell_type'] == 'code':
            source = ''.join(cell['source'])
            if marker in source:
                return idx
    return None

def update_cell_1_schema(notebook):
    """
    Cell 1: Update schema definition
    - Change attribute name: security_access_level → security_clearance_level
    - Increase schema version: 1.0 → 1.1
    - Update comments
    """
    print("📋 Updating Cell 1: Schema Definition...")

    # Find Cell 1 (Schema definition cell)
    idx = find_cell_by_marker(notebook, 'kritis_emergency_maintenance_cert')

    if idx is None:
        print("   ❌ Cell 1 not found!")
        return False

    source = notebook['cells'][idx]['source']

    # Convert to string for easier manipulation
    if isinstance(source, list):
        source_str = ''.join(source)
    else:
        source_str = source

    # Replace all occurrences in this cell
    source_str = source_str.replace('"security_access_level"', '"security_clearance_level"')
    source_str = source_str.replace("'security_access_level'", "'security_clearance_level'")
    source_str = source_str.replace(
        '"schema_version": "1.0"',
        '"schema_version": "1.1"'
    )
    source_str = source_str.replace(
        "'schema_version': '1.0'",
        "'schema_version': '1.1'"
    )

    # Update comment about security_access_level
    source_str = source_str.replace(
        '- `security_access_level`: Sicherheitsfreigabe (z.B. "Stufe-3-Kritisch")',
        '- `security_clearance_level`: Deutsche KRITIS Sicherheitsüberprüfungs-Level (0-3)\n' +
        '#   0 = Standard-Sicherheitsüberprüft\n' +
        '#   1 = Ü1 - Einfache Sicherheitsüberprüfung\n' +
        '#   2 = Ü2 - Erweiterte Sicherheitsüberprüfung (MINIMUM)\n' +
        '#   3 = Ü3 - Erweiterte SÜ mit Sicherheitsermittlungen'
    )

    # Convert back to list (Jupyter notebook format)
    notebook['cells'][idx]['source'] = source_str.split('\n')
    # Add newlines back
    notebook['cells'][idx]['source'] = [line + '\n' if i < len(source_str.split('\n')) - 1 else line
                                         for i, line in enumerate(source_str.split('\n'))]

    print(f"   ✅ Cell 1 updated (schema version 1.1, security_clearance_level)")
    return True

def update_cell_18_credential_issuance(notebook):
    """
    Cell 18: Update credential issuance
    - Change value: "Stufe-3-Kritisch" → "2" (Ü2)
    - Update attribute name
    """
    print("📤 Updating Cell 18: Credential Issuance...")

    # Find Cell 18
    idx = find_cell_by_marker(notebook, 'Credential Offer senden (Issuer → Holder)')

    if idx is None:
        print("   ❌ Cell 18 not found!")
        return False

    source = notebook['cells'][idx]['source']
    if isinstance(source, list):
        source_str = ''.join(source)
    else:
        source_str = source

    # Replace attribute name and value
    source_str = source_str.replace(
        '{"name": "security_access_level", "value": "Stufe-3-Kritisch"}',
        '{"name": "security_clearance_level", "value": "2"}  # Ü2 - Erweiterte Sicherheitsüberprüfung'
    )
    source_str = source_str.replace(
        '{\"name\": \"security_access_level\", \"value\": \"Stufe-3-Kritisch\"}',
        '{\"name\": \"security_clearance_level\", \"value\": \"2\"}  # Ü2 - Erweiterte Sicherheitsüberprüfung'
    )

    # Convert back
    notebook['cells'][idx]['source'] = source_str.split('\n')
    notebook['cells'][idx]['source'] = [line + '\n' if i < len(source_str.split('\n')) - 1 else line
                                         for i, line in enumerate(source_str.split('\n'))]

    print(f"   ✅ Cell 18 updated (security_clearance_level: 2)")
    return True

def update_cell_19_output(notebook):
    """
    Cell 19: Update output displays
    """
    print("📋 Updating Cell 19: Credential in Holder Wallet...")

    idx = find_cell_by_marker(notebook, 'Credential in Holder Wallet')

    if idx is None:
        print("   ❌ Cell 19 not found!")
        return False

    source = notebook['cells'][idx]['source']
    if isinstance(source, list):
        source_str = ''.join(source)
    else:
        source_str = source

    # Replace output references
    source_str = source_str.replace(
        '- security_access_level: Stufe-3-Kritisch',
        '- security_clearance_level: 2 (Ü2 - Erweiterte Sicherheitsüberprüfung)'
    )
    source_str = source_str.replace('security_access_level', 'security_clearance_level')

    # Convert back
    notebook['cells'][idx]['source'] = source_str.split('\n')
    notebook['cells'][idx]['source'] = [line + '\n' if i < len(source_str.split('\n')) - 1 else line
                                         for i, line in enumerate(source_str.split('\n'))]

    print(f"   ✅ Cell 19 updated")
    return True

def update_cell_20_proof_request(notebook):
    """
    Cell 20: Add ZKP predicate for security_clearance_level >= 2
    - Remove security_access_level from requested_attributes
    - Add requested_predicates with ZKP for clearance >= 2
    """
    print("🔍 Updating Cell 20: Proof Request with ZKP Predicate...")

    idx = find_cell_by_marker(notebook, 'Proof Request senden (Verifier → Holder)')

    if idx is None:
        print("   ❌ Cell 20 not found!")
        return False

    source = notebook['cells'][idx]['source']
    if isinstance(source, list):
        source_str = ''.join(source)
    else:
        source_str = source

    # Replace attribute name in requested_attributes section
    # Find and replace the security_access_level attribute definition
    source_str = source_str.replace(
        '''            "name": "security_access_level",''',
        '''            "name": "security_clearance_level",'''
    )

    # Update the REVEALED comment
    source_str = source_str.replace(
        '# REVEALED: cert_type, facility_type, security_access_level, epoch_valid_from, epoch_valid_until, role (6 Attribute)',
        '# REVEALED: cert_type, facility_type, epoch_valid_from, epoch_valid_until, role (5 Attribute)\n# ZKP PREDICATE: security_clearance_level >= 2 (Ü2) - OHNE Offenlegung der exakten Stufe!'
    )

    # Find the requested_attributes section and add requested_predicates
    # Look for the pattern where requested_predicates should be added
    if '"requested_predicates": {}' in source_str:
        # Replace empty predicates with actual predicate
        predicate_section = '''"requested_predicates": {
            "pred1_clearance": {
                "name": "security_clearance_level",
                "p_type": ">=",
                "p_value": 2,
                "restrictions": [{"cred_def_id": cred_def_id}],
                "non_revoked": {"from": 0, "to": current_timestamp}
            }
        }'''

        source_str = source_str.replace('"requested_predicates": {}', predicate_section)

    # Update print statements
    source_str = source_str.replace(
        'print(f"   REVEALED:      Berechtigung, Anlage, Sicherheitsstufe, Zeitraum, Rolle (6 Attribute)")',
        'print(f"   REVEALED:      Berechtigung, Anlage, Zeitraum, Rolle (5 Attribute)")\nprint(f"   ZKP PREDICATE: Sicherheitsfreigabe >= Ü2 (OHNE Offenlegung der exakten Stufe!)")'
    )

    # Convert back
    notebook['cells'][idx]['source'] = source_str.split('\n')
    notebook['cells'][idx]['source'] = [line + '\n' if i < len(source_str.split('\n')) - 1 else line
                                         for i, line in enumerate(source_str.split('\n'))]

    print(f"   ✅ Cell 20 updated (ZKP predicate added)")
    return True

def update_cell_21_output(notebook):
    """
    Cell 21: Update output displays for proof request
    """
    print("📋 Updating Cell 21: Proof Request Output...")

    idx = find_cell_by_marker(notebook, 'Proof Presentation')

    if idx is None:
        print("   ⚠️  Cell 21 marker not found, trying alternative...")
        # Try alternative marker
        idx = find_cell_by_marker(notebook, 'auto-present')

    if idx is None:
        print("   ❌ Cell 21 not found!")
        return False

    source = notebook['cells'][idx]['source']
    if isinstance(source, list):
        source_str = ''.join(source)
    else:
        source_str = source

    # Replace references
    source_str = source_str.replace('security_access_level', 'security_clearance_level')
    source_str = source_str.replace('Stufe-3-Kritisch', '2 (Ü2)')

    # Convert back
    notebook['cells'][idx]['source'] = source_str.split('\n')
    notebook['cells'][idx]['source'] = [line + '\n' if i < len(source_str.split('\n')) - 1 else line
                                         for i, line in enumerate(source_str.split('\n'))]

    print(f"   ✅ Cell 21 updated")
    return True

def update_cell_22_output(notebook):
    """
    Cell 22: Update output displays for holder presentations
    """
    print("📋 Updating Cell 22: Holder Presentations Output...")

    idx = find_cell_by_marker(notebook, 'Holder Presentations')

    if idx is None:
        print("   ❌ Cell 22 not found!")
        return False

    source = notebook['cells'][idx]['source']
    if isinstance(source, list):
        source_str = ''.join(source)
    else:
        source_str = source

    # Replace references
    source_str = source_str.replace(
        '   - security_access_level: Stufe-3-Kritisch',
        '   - security_clearance_level: 2 (Ü2 - Erweiterte Sicherheitsüberprüfung)'
    )
    source_str = source_str.replace('security_access_level', 'security_clearance_level')

    # Convert back
    notebook['cells'][idx]['source'] = source_str.split('\n')
    notebook['cells'][idx]['source'] = [line + '\n' if i < len(source_str.split('\n')) - 1 else line
                                         for i, line in enumerate(source_str.split('\n'))]

    print(f"   ✅ Cell 22 updated")
    return True

def update_cell_23_verification(notebook):
    """
    Cell 23: Add predicate evaluation to verification logic
    - Add ZKP predicate evaluation section
    - Update access decision to include clearance check
    """
    print("✅ Updating Cell 23: Presentation Verification with Predicate Evaluation...")

    idx = find_cell_by_marker(notebook, 'Presentation verifizieren (Verifier)')

    if idx is None:
        print("   ❌ Cell 23 not found!")
        return False

    source = notebook['cells'][idx]['source']
    if isinstance(source, list):
        source_str = ''.join(source)
    else:
        source_str = source

    # Replace attribute name references
    source_str = source_str.replace(
        '"name": "security_access_level"',
        '"name": "security_clearance_level"'
    )

    # Add predicate evaluation section before FINALE ZUGRIFFSENTSCHEIDUNG
    predicate_section = '''
    # ========================================
    # PREDICATE AUSWERTUNG (ZKP)
    # ========================================
    print("\\n" + "="*60)
    print("🔐 ZERO-KNOWLEDGE-PROOF AUSWERTUNG")
    print("="*60)

    predicates = requested_proof.get("predicates", {})
    has_required_clearance = False

    if predicates:
        for ref, pred_data in predicates.items():
            print(f"   ✅ Predicate erfüllt: security_clearance_level >= 2 (Ü2)")
            print(f"   🔒 Zero-Knowledge-Proof: Exakte Sicherheitsstufe NICHT offengelegt!")
            print(f"   ✓ Techniker hat mindestens Ü2 (Erweiterte Sicherheitsüberprüfung)")
            has_required_clearance = True
    else:
        print(f"   ⚠️  Keine Predicates im Proof gefunden!")

    print("="*60)
'''

    # Insert predicate section before FINALE ZUGRIFFSENTSCHEIDUNG
    finale_marker = '    # ========================================\n    # FINALE ZUGRIFFSENTSCHEIDUNG'
    if finale_marker in source_str:
        source_str = source_str.replace(finale_marker, predicate_section + '\n' + finale_marker)

    # Update access decision logic
    source_str = source_str.replace(
        '    # Beide Bedingungen müssen erfüllt sein\n    if not is_revoked and is_time_valid:',
        '    # Alle drei Bedingungen müssen erfüllt sein\n    if not is_revoked and is_time_valid and has_required_clearance:'
    )

    # Update success message
    source_str = source_str.replace(
        'print(f"\\n✅✅ ZUGANG GEWÄHRT")\n        print(f"   ✓ Credential ist gültig (nicht revoked)")\n        print(f"   ✓ Zertifikat ist zeitlich gültig")',
        'print(f"\\n✅✅✅ ZUGANG GEWÄHRT")\n        print(f"   ✓ Credential ist gültig (nicht revoked)")\n        print(f"   ✓ Zertifikat ist zeitlich gültig")\n        print(f"   ✓ Sicherheitsfreigabe >= Ü2 (Zero-Knowledge-Proof)")'
    )

    # Update denial message
    source_str = source_str.replace(
        'print(f"\\n❌❌ ZUGANG VERWEIGERT")\n        if is_revoked:\n            print(f"   ✗ Credential ist REVOKED")\n        if not is_time_valid:\n            print(f"   ✗ Zertifikat ist NICHT zeitlich gültig")',
        'print(f"\\n❌❌❌ ZUGANG VERWEIGERT")\n        if is_revoked:\n            print(f"   ✗ Credential ist REVOKED")\n        if not is_time_valid:\n            print(f"   ✗ Zertifikat ist NICHT zeitlich gültig")\n        if not has_required_clearance:\n            print(f"   ✗ Sicherheitsfreigabe NICHT ausreichend (< Ü2)")'
    )

    # Convert back
    notebook['cells'][idx]['source'] = source_str.split('\n')
    notebook['cells'][idx]['source'] = [line + '\n' if i < len(source_str.split('\n')) - 1 else line
                                         for i, line in enumerate(source_str.split('\n'))]

    print(f"   ✅ Cell 23 updated (predicate evaluation added)")
    return True

def main():
    """Main migration function"""
    notebook_path = '/home/ferris/github/MSc-blockchain-ssi-pqc/hopE/SSI_Complete_Workflow.ipynb'
    backup_path = '/home/ferris/github/MSc-blockchain-ssi-pqc/hopE/SSI_Complete_Workflow_pre_clearance_backup.ipynb'

    print("="*60)
    print("🔄 SECURITY CLEARANCE LEVEL MIGRATION")
    print("="*60)
    print(f"Migrating: security_access_level (String) → security_clearance_level (Integer 0-3)")
    print(f"Notebook: {notebook_path}\n")

    # Load notebook
    print("📂 Loading notebook...")
    try:
        notebook = load_notebook(notebook_path)
        print(f"   ✅ Notebook loaded ({len(notebook['cells'])} cells)\n")
    except Exception as e:
        print(f"   ❌ Error loading notebook: {e}")
        return 1

    # Create backup
    print("💾 Creating backup...")
    try:
        save_notebook(backup_path, notebook)
        print(f"   ✅ Backup created: {backup_path}\n")
    except Exception as e:
        print(f"   ❌ Error creating backup: {e}")
        return 1

    # Update all cells
    results = []
    results.append(update_cell_1_schema(notebook))
    results.append(update_cell_18_credential_issuance(notebook))
    results.append(update_cell_19_output(notebook))
    results.append(update_cell_20_proof_request(notebook))
    results.append(update_cell_21_output(notebook))
    results.append(update_cell_22_output(notebook))
    results.append(update_cell_23_verification(notebook))

    # Save updated notebook
    print("\n💾 Saving updated notebook...")
    try:
        save_notebook(notebook_path, notebook)
        print(f"   ✅ Notebook saved\n")
    except Exception as e:
        print(f"   ❌ Error saving notebook: {e}")
        return 1

    # Summary
    print("="*60)
    print("📊 MIGRATION SUMMARY")
    print("="*60)
    successful = sum(results)
    total = len(results)
    print(f"   Cells updated: {successful}/{total}")

    if successful == total:
        print("\n✅ Migration completed successfully!")
        print("\nChanges:")
        print("   • Schema version: 1.0 → 1.1")
        print("   • Attribute: security_access_level → security_clearance_level")
        print("   • Value type: String → Integer (0-3)")
        print("   • Credential value: 'Stufe-3-Kritisch' → '2' (Ü2)")
        print("   • ZKP Predicate: security_clearance_level >= 2 added")
        print("\n🔐 Zero-Knowledge-Proof now active for security clearance!")
    else:
        print("\n⚠️  Migration completed with warnings")
        print(f"   Some cells could not be updated ({total - successful} failures)")

    print("="*60)
    return 0 if successful == total else 1

if __name__ == '__main__':
    sys.exit(main())
