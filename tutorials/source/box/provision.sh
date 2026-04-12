#!/bin/bash -ex
#
# Provisioning script to prepare the box used in the tutorial

# Make sure that apt in this provisioning script runs non-interactively
export DEBIAN_FRONTEND=noninteractive

# Make sure that apt in the tutorial runs non-interactively
echo "export DEBIAN_FRONTEND=noninteractive" >> /home/vagrant/.profile
echo "export DEBIAN_FRONTEND=noninteractive" >> /root/.profile

# Update the system
apt-get update
apt-get dist-upgrade -y

# Remove unattended-upgrades, this sometimes causes apt-get in the main
# tutorial to fail
apt-get remove -y unattended-upgrades

# Allow the root user to log in with the same credentials.
# The tutorial assumes root access.
echo "PermitRootLogin Yes" >> /etc/ssh/sshd_config

mkdir -p /root/.ssh
cp /home/vagrant/.ssh/authorized_keys /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys