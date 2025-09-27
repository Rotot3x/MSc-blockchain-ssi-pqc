#!/usr/bin/env python3
"""
ACA-Py Demo Integration Script for PQCrypto_FM

This script modifies the standard ACA-Py demo to use PQC cryptography
by default, integrating with the run_demo functionality.
"""

import sys
import os
import argparse
import subprocess
import json
from pathlib import Path

# Add the demo directory to path
demo_dir = Path(__file__).parent
acapy_root = demo_dir.parent
sys.path.insert(0, str(demo_dir))
sys.path.insert(0, str(acapy_root))

def setup_pqc_demo_config():
    """Create PQC-enabled configuration for demo agents."""
    
    pqc_config_base = {
        "plugin": ["pqcrypto_fm.v1_0"],
        "plugin-config": {
            "pqcrypto_fm.v1_0": {
                "enable_demo_mode": True,
                "hybrid_mode": True,
                "require_pqc_for_new_connections": True,
                "min_security_level": 3,
                "default_kem_algorithm": "Kyber768",
                "default_sig_algorithm": "Dilithium3",
                "enable_pqc_for_credentials": True,
                "enable_pqc_for_proofs": True,
                "use_askar_anoncreds": True,
            }
        },
        "wallet-type": "askar-anoncreds",
        "wallet-storage-type": "default"
    }
    
    # Agent-specific configurations
    agent_configs = {
        "faber": {
            **pqc_config_base,
            "plugin-config": {
                "pqcrypto_fm.v1_0": {
                    **pqc_config_base["plugin-config"]["pqcrypto_fm.v1_0"],
                    "demo_algorithms": {"faber": "Dilithium3"}
                }
            }
        },
        "alice": {
            **pqc_config_base,
            "plugin-config": {
                "pqcrypto_fm.v1_0": {
                    **pqc_config_base["plugin-config"]["pqcrypto_fm.v1_0"],
                    "demo_algorithms": {"alice": "Kyber768"}
                }
            }
        },
        "acme": {
            **pqc_config_base,
            "plugin-config": {
                "pqcrypto_fm.v1_0": {
                    **pqc_config_base["plugin-config"]["pqcrypto_fm.v1_0"],
                    "demo_algorithms": {"acme": "Dilithium3"}
                }
            }
        },
        "performance": {
            **pqc_config_base,
            "plugin-config": {
                "pqcrypto_fm.v1_0": {
                    **pqc_config_base["plugin-config"]["pqcrypto_fm.v1_0"],
                    "demo_algorithms": {"performance": "Kyber512"},
                    "hardware_acceleration": True,
                    "batch_operations": True
                }
            }
        }
    }
    
    return agent_configs

def patch_demo_runner():
    """Patch the demo runner to support PQC flags."""
    
    print("🔧 Patching ACA-Py demo runner for PQC support...")
    
    # Create PQC-specific demo configurations
    pqc_configs = setup_pqc_demo_config()
    
    # Write configurations to temporary files
    config_dir = demo_dir / "pqc_configs"
    config_dir.mkdir(exist_ok=True)
    
    for agent, config in pqc_configs.items():
        config_file = config_dir / f"{agent}_pqc.yml"
        
        # Convert to YAML format
        yaml_content = []
        for key, value in config.items():
            if key == "plugin":
                yaml_content.append(f"plugin:")
                for plugin in value:
                    yaml_content.append(f"  - {plugin}")
            elif key == "plugin-config":
                yaml_content.append(f"plugin-config:")
                for plugin_name, plugin_config in value.items():
                    yaml_content.append(f"  {plugin_name}:")
                    for setting, setting_value in plugin_config.items():
                        if isinstance(setting_value, dict):
                            yaml_content.append(f"    {setting}:")
                            for sub_key, sub_value in setting_value.items():
                                yaml_content.append(f"      {sub_key}: {sub_value}")
                        else:
                            yaml_content.append(f"    {setting}: {setting_value}")
            else:
                yaml_content.append(f"{key}: {value}")
        
        with open(config_file, 'w') as f:
            f.write('\n'.join(yaml_content))
        
        print(f"   ✅ Created PQC config for {agent}: {config_file}")
    
    return config_dir

def run_pqc_demo(agents=None, performance=False, no_auto=False):
    """Run the ACA-Py demo with PQC enabled."""
    
    print("🚀 Starting ACA-Py Demo with PQCrypto_FM...")
    print("   📊 Quantum-Safe Cryptography: ENABLED")
    print("   🔐 Algorithms: Kyber768 + Dilithium3")
    print("   💾 Wallet: Askar-AnonCreds")
    print("")
    
    # Patch demo configuration
    config_dir = patch_demo_runner()
    
    # Set up environment
    env = os.environ.copy()
    env.update({
        "ACAPY_PQC_ENABLED": "1",
        "ACAPY_PQC_CONFIG_DIR": str(config_dir),
        "ACAPY_WALLET_TYPE": "askar-anoncreds"
    })
    
    # Base demo command
    demo_cmd = [
        sys.executable, 
        str(demo_dir / "run_demo"),
        "--wallet-type", "askar-anoncreds"
    ]
    
    # Add PQC-specific arguments
    demo_cmd.extend([
        "--plugin", "pqcrypto_fm.v1_0",
        "--plugin-config-value", "pqcrypto_fm.v1_0.enable_demo_mode=true",
        "--plugin-config-value", "pqcrypto_fm.v1_0.hybrid_mode=true",
    ])
    
    # Agent-specific configuration
    if agents:
        demo_cmd.extend(agents)
    
    if performance:
        demo_cmd.extend([
            "--timing",
            "--plugin-config-value", "pqcrypto_fm.v1_0.hardware_acceleration=true"
        ])
        print("   ⚡ Performance mode: ENABLED")
    
    if no_auto:
        demo_cmd.append("--no-auto")
        print("   🎮 Manual mode: ENABLED")
    
    print(f"📋 Demo command: {' '.join(demo_cmd)}")
    print("")
    
    # Run the demo
    try:
        result = subprocess.run(demo_cmd, env=env, cwd=demo_dir)
        if result.returncode == 0:
            print("✅ PQC Demo completed successfully!")
            print_pqc_summary()
        else:
            print(f"❌ PQC Demo failed with return code: {result.returncode}")
        return result.returncode
    except KeyboardInterrupt:
        print("\n🛑 PQC Demo interrupted by user")
        return 130
    except Exception as e:
        print(f"❌ Error running PQC demo: {e}")
        return 1

def print_pqc_summary():
    """Print summary of PQC demo results."""
    
    print("\n" + "="*60)
    print("🎯 PQCrypto_FM Demo Summary")
    print("="*60)
    print("")
    print("✅ Quantum-Safe Features Demonstrated:")
    print("   • Post-Quantum Key Exchange (Kyber768)")
    print("   • Quantum-Safe Digital Signatures (Dilithium3)")
    print("   • Hybrid Cryptography (PQC + Classical)")
    print("   • Askar-AnonCreds Wallet Integration")
    print("   • Quantum-Safe Credential Issuance")
    print("   • PQC-enabled Proof Verification")
    print("")
    print("🔐 Security Level: NIST Level 3 (Recommended)")
    print("💾 Wallet Type: Askar-AnonCreds")
    print("🌐 Protocol: DIDComm v2 with PQC Extensions")
    print("")
    print("📊 Next Steps:")
    print("   • Review agent logs for PQC operations")
    print("   • Check /pqc/stats API for performance metrics")
    print("   • Explore hybrid vs pure PQC modes")
    print("   • Test with different security levels")
    print("")
    print("🔗 More Info: https://plugins.aca-py.org/pqcrypto_fm")
    print("="*60)

def check_pqc_requirements():
    """Check if PQC requirements are available."""
    
    print("🔍 Checking PQC requirements...")
    
    # Check liboqs-python
    try:
        import oqs
        print("   ✅ liboqs-python: Available")
    except ImportError:
        print("   ❌ liboqs-python: Missing")
        print("   💡 Install with: pip install liboqs-python")
        return False
    
    # Check PQCrypto_FM plugin
    try:
        import pqcrypto_fm
        print("   ✅ PQCrypto_FM plugin: Available")
    except ImportError:
        print("   ❌ PQCrypto_FM plugin: Missing")
        print("   💡 Install from acapy-plugins repository")
        return False
    
    # Check Askar
    try:
        from aries_cloudagent.wallet.askar import AskarWallet
        print("   ✅ Askar wallet: Available")
    except ImportError:
        print("   ❌ Askar wallet: Missing")
        print("   💡 Ensure ACA-Py >= 1.0.0 with Askar support")
        return False
    
    print("   ✅ All PQC requirements satisfied!")
    return True

def main():
    """Main entry point for PQC demo runner."""
    
    parser = argparse.ArgumentParser(
        description="Run ACA-Py demo with PQCrypto_FM plugin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_pqc_demo.py                    # Run full demo with PQC
  python run_pqc_demo.py --performance      # Run with performance testing
  python run_pqc_demo.py --no-auto         # Run in manual mode
  python run_pqc_demo.py --agents faber    # Run only Faber agent
  python run_pqc_demo.py --check           # Check requirements only
        """
    )
    
    parser.add_argument(
        "--agents", 
        nargs="*",
        choices=["faber", "alice", "acme", "performance"],
        help="Specific agents to run (default: all)"
    )
    
    parser.add_argument(
        "--performance", 
        action="store_true",
        help="Enable performance testing and benchmarks"
    )
    
    parser.add_argument(
        "--no-auto", 
        action="store_true",
        help="Disable auto-accept for manual demonstration"
    )
    
    parser.add_argument(
        "--check", 
        action="store_true",
        help="Check PQC requirements and exit"
    )
    
    args = parser.parse_args()
    
    # Check requirements
    if not check_pqc_requirements():
        return 1
    
    if args.check:
        print("\n✅ PQC requirements check passed!")
        return 0
    
    # Run the demo
    return run_pqc_demo(
        agents=args.agents,
        performance=args.performance,
        no_auto=args.no_auto
    )

if __name__ == "__main__":
    sys.exit(main())