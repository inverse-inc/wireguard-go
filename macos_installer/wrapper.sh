#!/bin/bash

h=$HOME

echo Please enter your sudo password if prompted to:

d=`dirname "$0"`
sudo "$d/wireguard-go" $h/.wgenv

read -p "Press any key to close"

