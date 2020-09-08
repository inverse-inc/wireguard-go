#!/bin/bash

echo Please enter your sudo password if prompted to:

d=`dirname "$0"`
sudo "$d/wireguard-go"

read -p "Press any key to close"

