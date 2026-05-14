// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package agent

// Version is the agent binary version. It is injected at build time from the
// latest Git tag by the Makefile (make all). Defaults to "dev" for local builds
// that bypass the Makefile.
var Version = "dev"
