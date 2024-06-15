#! /bin/sh

# Build the Catlog2 image
podman build \
  --tag catalog2:latest \
  .
