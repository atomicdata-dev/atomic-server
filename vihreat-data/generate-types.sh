set -e

here=$(dirname $(realpath $0))

# Start atomic-server in the background
source $here/with-atomic-server-in-background.sh

# Regenerate the .ts files describing our ontology
cd $here/../browser/vihreat-lib
pnpm install
pnpm run generate-ontologies

# Rebuild (with the new .ts files built just now)
cd $here/../browser
pnpm run build