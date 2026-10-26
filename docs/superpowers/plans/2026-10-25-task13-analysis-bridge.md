# Task13 analysis bridge implementation

Scope: the free E1 artifact verifier and explicit product import entry. No current
36-analysis inputs, paid calls, approvals, real databases or retained resources
are changed. E2 worker export/runtime and live PostgreSQL acceptance remain open.

1. Write artifact replay and graph-boundary tests; run them red.
2. Implement a hash-bound, answer-free source manifest verifier. Recreate the
   fixed seed from raw events; bind slot/request/result/stdout/condition/HTTP
   body/response/returned knowledge, replay schema/citation/registry checks and
   reject non-attack or untraceable targets. Freeze first-three selection in the
   original 36-row order without confidence or truth inputs.
3. Add an immutable verified product payload and dedicated workflow constructor.
   Import executes a real node, verifies persisted evidence, seals once, then
   runs existing respond/save_result/approval interrupt. Ordinary initial state
   and the six-role route retain their old behavior. Exact 1800-second TTL is
   checked before saving respond output.
4. Verify pending reopen and durable started/unknown replay refusal; run relevant
   graph/response/retained-export regressions. Report exact tests and limitations.

Synthetic fixtures and MemorySaver validate software behavior only. They are not
live PostgreSQL resources, retained checkpoints, human decisions or timing proof.
