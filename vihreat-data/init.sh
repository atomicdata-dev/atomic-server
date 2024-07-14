set -e

here=$(dirname $(realpath $0))

# (Re)generate the JSONs
cd $here
python3 generate.py

# cd into repository root
cd ..

# Make sure the server is up to date
cargo build

# Wipe out existing database (the user will need to confirm with "y").
# Fails if database does not exist in the first place, so we suppress failures here.
./target/debug/atomic-server reset || true

# Import bootstrap data
./target/debug/atomic-server import --file $here/json/ontology.json --force
for file in $here/json/p*.json
do 
    ./target/debug/atomic-server import --file $file --force
done

# Export
./target/debug/atomic-server export -p $here/json/debug_export.json

# Typescript types
$here/generate-types.sh