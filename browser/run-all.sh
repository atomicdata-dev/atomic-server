#!/bin/bash

# Check if an argument is provided
if [ $# -eq 0 ]; then
  echo "No arguments provided. Usage: ./run-all.sh [script]"
  exit 1
fi

# The script to run (e.g., build, test, lint)
script=$1

# Define your list of projects
declare -a projects=("lib" "react" "cli" "svelte" "data-browser")

# Loop over the list of projects
for project in "${projects[@]}"; do
  dir="$project"
  if [ -d "$dir" ]; then
    echo "Running 'bun run $script' in $dir"
    # Navigate into the directory, run 'bun run [script]', and then go back
    (cd "$dir" && bun run $script)
  else
    echo "Directory $dir does not exist."
  fi
done
