# E2 host trial controller implementation plan

Goal: add the concrete host orchestration for the already approved E2 architecture without registering or spending any real scope, epoch, journal, service, or approval.

Only new files: `scripts/task13_e_trial.py`, `evals/tests/test_e_trial_controller.py`, this plan, and the focused audit report. Existing production modules stay unchanged.

- [x] Write free synthetic tests for independently pinned external inputs, once-only host dispatch, unknown preservation, actual chat evidence, exact packet/resource/source bindings, protocol and review-window rejection, and timing/lifecycle delegation.
- [x] Run the new test file red using the original backend venv with this tree on PYTHONPATH, SSLKEYLOGFILE removed, cache disabled, and a unique temporary directory.
- [x] Implement a frozen host manifest and explicit `readiness/status/plan/read/decision/trial` API. Defaults call the dedicated actual runtime wrappers. Free dependency injection is allowed only with synthetic registrations and evidence.
- [x] Preflight the original registered journal/epoch/source/runtime before paid dispatch; independently require this new host entrypoint in the epoch export. Never create authority or registration.
- [x] Save an exclusive immutable start marker before each plan or decision dispatch. Preserve actual runtime results/stdout and original pending artifact bytes; ambiguity remains unknown and cannot replay.
- [x] Require an externally pinned actual user chat record for the exact live packet before a decision. Verify zero-model review receipts, actual product DB approval receipt, and isolation. Keep approved state separate from retained pending state.
- [x] Build the exact existing timing v2 approved-source shape and run ETimingCampaign with the actual verification wrapper, HostWorkerLifecycleVerifier, registered execution admission, and a fresh actual product DB approval verifier.
- [ ] Run focused tests and lint; document interfaces, evidence formats, and real-call limitations. No commit or real experiment.
