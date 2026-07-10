# Machine specific info

## Rust Cache/Target

On this machine, a rust shared target dir is configured pointing to `/Volumes/DevCache/.cargo/shared-target`.
Any rust build will use this shared target dir. Make sure tooling is configured to handle this (Do not hardcode this path as that would brake the project for other machines).

## Dagger

Dagger runs in docker which slows down the machine and eats up disk space.
On this machine, dagger is configured to run on a PC downstairs (the same machine running the github CI).
This is done by setting `DOCKER_HOST=ssh://joep@192.168.0.89`.
