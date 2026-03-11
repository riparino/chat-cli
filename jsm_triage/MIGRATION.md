# Migration note: prototype helpdesk triage -> IAM/JSM production triage

## What changed
- Replaced generic helpdesk schema with IAM/access-management triage schema (`request_type`, `approval_type`, `missing_fields`, `knowledge_sources_used`, etc.).
- Added explicit grounding layers:
  - Local curated policy/rules/examples under `config/`.
  - Optional Rovo/Confluence retrieval through `retrieve_knowledge`.
- Added explicit feedback loop and review workflow (`feedback`, `review-rules`, `export-examples`).
- Added audit logging (`data/triage_audit.jsonl`) for provider/sources/rationale traceability.
- Added config validation command and safe-by-default feature flags.

## Backward compatibility
- Provider chain and JSM client remain in place.
- Existing triage/watch/chat commands still work.
- Writeback behavior is now guarded by feature flags and dry-run defaults.

## Operational changes
1. Create policy and routing files in `config/` (templates included).
2. Run `jsm-triage validate-config` before production.
3. Use `jsm-triage knowledge-test --query "..."` to verify grounding.
4. Enable writeback flags explicitly in `config/feature_flags.yaml` only after validation.
