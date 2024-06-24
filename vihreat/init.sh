set -e

# cd into repository root
cd $(dirname $(realpath $0))
cd ..

# Make sure the server is up to date
cargo build

# Wipe out existing database (the user will need to confirm with "y").
# Fails if database does not exist in the first place, so we suppress failures here.
./target/debug/atomic-server reset || true

# Import bootstrap data
./target/debug/atomic-server import --file vihreat/data/ontology.json --force

# Export
./target/debug/atomic-server export -p vihreat/debug_export.json