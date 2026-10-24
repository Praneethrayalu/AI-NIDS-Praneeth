#!/usr/bin/env bash
# Reproduce everything from scratch: data -> training -> evaluation -> tests.
set -euo pipefail
cd "$(dirname "$0")"
export MPLBACKEND=Agg
python -m nids generate --seed 42 --train 3        # 5 scenario pcaps + 12 training pcaps (~8 min, scapy is slow)
python -m nids train --rebuild                     # extract training windows, grouped CV, fit models
python -m nids evaluate                            # metrics + figures into results/
python -m evaluation.architecture                  # architecture diagram
python -m pytest -q tests
