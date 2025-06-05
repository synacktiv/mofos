#!/bin/bash

TAG=$1
NAME=$2
OS=$3
DISTRIB=$4
HOSTNAME=$5

if [ -z "${TAG}" ] || [ -z "${NAME}" ] ; then
  exit 1
fi

systemctl --user start "vm-xpra@${NAME}"
systemctl --user start ssh-agent-proxy.service
systemctl --user start sudo-auth-proxy.service
