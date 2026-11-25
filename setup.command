#!/bin/bash
# Double-click on a Mac to run the guided setup in Terminal.
cd "$(dirname "$0")" || exit 1
bash scripts/setup.sh
echo
read -r -p "Press Return to close this window." _
