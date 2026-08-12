# PADAGONIA Integration Roadmap

Padagonia is the history and analysis layer; Locksmith remains the live lease
authority. Apply `/home/sal/padagonia/docs/enterprise-integration-directives.md`.

## Modules

- `lease_event_adapter`: record acquisition, renewal, release, expiry, queue,
  conflict, and recovery events.
- `resource_mapper`: map hierarchical resources and agents to stable graph IDs.
- `audit_reader`: query ownership history and contention without changing live
  authorization decisions.
- `retention_export`: produce incident timelines and bounded audit archives.

## Acceptance gates

No graph read can grant authority, duplicate events are suppressed, and lease
history remains recoverable after daemon restart.
