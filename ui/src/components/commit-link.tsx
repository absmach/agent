// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

import { commitUrl } from "@/lib/agent";
import { cn } from "@/lib/utils";

interface CommitLinkProps {
  commit?: string;
  /** Show the hash truncated to its first 10 characters. */
  short?: boolean;
  className?: string;
}

export function CommitLink({
  commit,
  short = false,
  className,
}: CommitLinkProps) {
  const fallback = "—";
  const label = !commit ? fallback : short ? commit.slice(0, 10) : commit;
  const url = commitUrl(commit);

  if (!url) {
    return <span className={cn(className)}>{label}</span>;
  }

  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className={cn(
        "text-primary underline-offset-2 hover:underline",
        className,
      )}
    >
      {label}
    </a>
  );
}
