#!/bin/sh
# vim: syntax=sh

# Generate Keys first
python3.6 generateKeyU1.py
python3.6 generateKeyU2.py

# Generate Certs
python3.6 createU1Cert.py
python3.6 createU2Cert.py

# Write message
python3.6 createU1Message.py

# Read Message
python3.6 readU1Message.py
