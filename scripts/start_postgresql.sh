#! /bin/sh
podman run \
  -dt \
  --rm \
  --name catalog_postgresql \
  --env POSTGRES_USER=catalog2 \
  --env POSTGRES_PASSWORD=password \
  --env POSTGRES_DB=catalog2 \
  --volume catalog_postgresql:/var/lib/postgresql/data \
  --publish 5432:5432 \
  docker.io/library/postgres:alpine
