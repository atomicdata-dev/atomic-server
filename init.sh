set -e

root=$(dirname $(realpath $0))
data=$root/vihreat-data

# (Re)generate the JSONs
cd $data
python3 generate.py

# Make sure the server is up to date
cd $root
cargo build

# Wipe out existing database (the user will need to confirm with "y").
# Fails if database does not exist in the first place, so we suppress failures here.
./server.sh reset || true

# Import bootstrap data
./server.sh import --file $data/json/ontology.json --force
for file in $data/json/p*.json
do 
    ./server.sh import --file $file --force
done

# Export
./server.sh export -p $data/json/debug_export.json

# Typescript types
$data/generate-types.sh