# Task13 human16 optional anytime successor

Prospective operating note, 2026-11-02. This implementation creates no actual
scope approval, factual judgment, request, execution slot, budget or timing credit.
It applies only to the new registered sixteen-slot B2/B3 sample. The original
64-slot judgments, original human-plan/order bytes, samples and denominators stay
unchanged.

Default `prepare_reviews(plan_pin, order_pin, rows)` still emits the original
`task13-human-review-prepared-v2` envelope. Its actual user reply must arrive in
19:00–24:00 Asia/Shanghai; midnight is outside that legacy interval. Passing an
unrelated external scope to legacy validation does not upgrade its semantics.

For a future formal176/F8 joint packet, the optional
`human_review_participation` section uses strict schema
`task13-human16-participation-v1`. Its exact fields are `schema_version`,
`review_window=anytime`, `reviewer=user`,
`applies_to=new-registered-sixteen-slot-sample-only`,
`judgment_mode=individual-actual-user`, enclosing `campaign_id` and
`bundle_sha256`, plus the original raw `human_plan`, `presentation_order` and
retained actual-user `anytime_authorization` pins. The pinned actual instruction
is the startup-recovery record with raw SHA256
`decdef181118f852fbde86758f8ee2660a6fb2f0d556364df25b125d1cec4035`.
The F8 engineering participation policy alone confers no human-review exception.
Unknown, malformed or additional human policy fields fail closed.

Prepare the concrete future section only after its actual formal bundle exists.
The existing concrete joint question must disclose that these sixteen factual
reviews may be delivered and answered at any time without continuous presence.
Each available slot still needs a separate actual question and the user's fresh
claim judgments with basis and top-five citation relevance judgments. No
automatic response-plan approval or old factual credit is added. The existing
engineering recovery approval and subsequent formal joint approval remain
separate. No extra preliminary approval or placeholder consent is required.

After retaining the actual joint approval, call:

```python
prepared = prepare_reviews(
    plan_pin, order_pin, rows,
    joint_scope_pin=scope_pin, joint_decision_pin=actual_decision_pin,
)
```

Both keyword pins are required together. The explicit valid section produces
`task13-human-review-prepared-v3`, adding `joint_scope`, `joint_decision`, and
`human_review_participation` outside the unchanged blind records. Persist with
the existing immutable writer. The actual decision binds the complete scope through
its raw hash and activates the successor. Prepared binds both raw
pins and actual outputs; each capture binds prepared. No future prepared,
output, capture or decision hash belongs in the initial human subsection.

Validate v3 with the independently selected exact same external pins:

```python
reviews = validate_reviews(
    prepared_pin, actual_capture_pins, rows,
    joint_scope_pin=scope_pin, joint_decision_pin=actual_decision_pin,
)
```

Presentations and replies must be aware, nonfuture and no earlier than the
activating decision. The original prefix order, distinct actual tool question
IDs, fresh individual user replies, all claim bases, citation judgments and
optional same-session monotonic checks remain mandatory. Wall timestamps record
receipt only; elapsed observations never claim active reading time. Missing
outputs keep their objective unavailable reasons in the same sixteen-slot
denominator. Offline factual submissions have no new upper deadline; the formal
Nov 5 deadline continues to govern execution admission.

`score_bundle` reuses the exact scope/decision pins returned by its sealed native
host/joint audit; prepared content cannot nominate scoring authority. It exports
the effective `review_window`, optional `human_review_participation` and their
joint scope/decision pins under `human_review`. Scores remain
`independent_intermediate`. Frozen-scope auditing validates the optional section
without entering execution admission, including after the admission deadline.

Readiness requires these bridge bytes in the actual final source freeze before
paid timing. A future bundle/question compiler must explicitly add the section
and disclosure; merely installing this optional support does not create a scope
or activate anytime factual review. Retain actual incoming UI records; local JSON
provenance validation cannot establish the honesty of operator-authored records.
