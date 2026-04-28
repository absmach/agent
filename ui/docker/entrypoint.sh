#!/bin/sh

# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

# The Next.js standalone server reads PORT and HOSTNAME from the environment.
# AGENT_BASE_URL is read at request time by the API proxy routes.
export PORT="${MG_UI_PORT:-3000}"
export HOSTNAME="0.0.0.0"

exec "$@"
