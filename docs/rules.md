# PromptShield Rules

## PS001 — Hard-coded secret

Detects credential-like assignments in source.

## PS002 — Prompt injection indicator

Detects common instruction-override and prompt-leakage phrases.

## PS003 — Dangerous tool capability

Flags command execution and destructive tool names for review.

## PS004 — External endpoint

Flags agent/tool-related references to external URLs.

## PS005 — Secret in environment file

Flags credential-like values in `.env` files. A `.env` file should normally be excluded from version control.

## PS006 — Insecure HTTP endpoint

Flags unencrypted HTTP URLs.

## PS007 — Wildcard tool permission

Flags broad permissions such as `*` or `allow_all`.

## PS008 — Tool confirmation disabled

Flags configuration patterns that appear to bypass user confirmation.

## PS009 — Broad data access

Flags configurations that may expose large filesystem/data scopes.

## PS010 — Private-key material

Detects PEM private-key headers.
