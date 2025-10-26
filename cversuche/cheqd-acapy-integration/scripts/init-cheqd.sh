#!/bin/sh
# Initialize cheqd node for local testing

# Check if already initialized
if [ ! -d /root/.cheqdnode/config ]; then
    echo "Initializing cheqd node..."

    # Initialize node
    cheqd-noded init test-node --chain-id cheqd-local

    # Update genesis to use ncheq as bond denom BEFORE creating gentx
    # Replace stake with ncheq in all relevant sections
    sed -i.bak \
        -e 's/"bond_denom": "stake"/"bond_denom": "ncheq"/g' \
        -e 's/"mint_denom": "stake"/"mint_denom": "ncheq"/g' \
        -e 's/"denom": "stake"/"denom": "ncheq"/g' \
        /root/.cheqdnode/config/genesis.json

    # Add validator key
    cheqd-noded keys add validator --keyring-backend test

    # Add genesis account
    cheqd-noded genesis add-genesis-account validator 100000000000ncheq --keyring-backend test

    # Create gentx
    cheqd-noded genesis gentx validator 1000000000ncheq --chain-id cheqd-local --keyring-backend test

    # Collect gentxs
    cheqd-noded genesis collect-gentxs

    # Configure app.toml
    sed -i.bak 's/minimum-gas-prices = ""/minimum-gas-prices = "25ncheq"/g' /root/.cheqdnode/config/app.toml
    sed -i.bak 's/enable = false/enable = true/g' /root/.cheqdnode/config/app.toml

    # Configure config.toml
    sed -i.bak 's/laddr = "tcp:\/\/127.0.0.1:26657"/laddr = "tcp:\/\/0.0.0.0:26657"/g' /root/.cheqdnode/config/config.toml

    echo "Initialization complete!"
fi

# Start the node
echo "Starting cheqd node..."
exec cheqd-noded start
