# Generates typescript types for the ontology
set -e

here=$(dirname $(realpath $0))

# Start the server in the background (generate-ontologies needs it to be running)
cd $here/..
( ./target/debug/atomic-server &> /dev/null & )
sleep 2

# Generate the ontologies
cd $here/../browser/vihreat-lib
pnpm install
pnpm run generate-ontologies
pnpm run build

# Finally, kill the server
pkill atomic-server