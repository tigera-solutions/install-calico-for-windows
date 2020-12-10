#!/usr/bin/env bash

mkdir ~/.docker
cp ~/setup/pull-secret.json ~/.docker/config.json
docker pull quay.io/tigera/calicoctl:v3.4.0
docker create --name calicoctl-copy quay.io/tigera/calicoctl:v3.4.0
docker cp calicoctl-copy:/calicoctl calicoctl
docker rm calicoctl-copy
chmod +x calicoctl
sudo mv calicoctl /usr/local/bin
rm -rf ~/.docker
