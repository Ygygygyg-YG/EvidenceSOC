# E3 timing bootstrap implementation

Scope: free controller engineering in the isolated stage-E tree. No model, real
approval, retained product state, budget ledger, or container will be created.

1. Write synthetic tests first for fixed first-three registration and immutable
   F8/core/source identities; observe the missing-controller failure.
2. Implement a small independent append-only controller, reusing the existing
   request, approval/input and worker-result validators. Keep formal verification
   unchanged. Persist started before dispatch and never replay bound trials.
3. Test bootstrap TTL/provisional M, hard deadlines, independent resources,
   cancellation with trusted host lifecycle proof, recovery and tampering.
4. Export only after three complete trials, then pass the artifact through the
   existing formal timing parser. Synthetic artifacts remain explicitly marked.
5. Run E3 and existing verification tests with a unique temporary directory;
   report exact checks and the missing real runtime lifecycle integration.

The host lifecycle verifier is mandatory and independent from worker output.
Until the runtime provides inspected termination/reclamation evidence, this
controller has no production-ready execution adapter. A fixture is never a real
trial or approval. The original formal >=3-trial gate is not modified.
