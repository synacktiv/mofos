#!/bin/bash

# During template installation, the machine is not yet managed by mofos,
# the inventory would not working.
# A custom inventory is created on the fly using the given tag as main ansible
# group and the distribution as secondary.

TAG=$1
NAME=$2
OS=$3
DISTRIB=$4
HOSTNAME=$5

if [ -z "${TAG}" ] || [ -z "${NAME}" ] || [ -z "${DISTRIB}" ] ; then
  exit 1
fi

echo "Done."
