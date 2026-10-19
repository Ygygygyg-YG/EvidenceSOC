# Task13 preregistered evaluation protocol

Protocol `task13-v1`, registered 2026-10-18 Asia/Shanghai before any formal model output. Design authority: [Task13 design](../superpowers/specs/2026-10-18-task13-design.md). Implementation progress is separate from formal completion. Existing Task12 data and acceptance records are immutable.

## Authorization, model and resource limits

User authorized total CNY100 including all model attempts, failures, development and simulation; development subset <=CNY15. Reviewer/approver is the user, available 19:00–00:00 Asia/Shanghai. Availability does not approve a response plan. Plan approval uses original product hashes and individually recorded decisions. Do not fabricate approval or semantic review.

Model request `deepseek-flash`; published service version `DeepSeek-V4.1-Flash-1017`, checked 2026-10-18T13:02:05Z. Alias cannot independently prove fixed weights. Explicit nonthinking, temperature0, JSON object output with Pydantic validation, max4096 output tokens and max65536 context UTF-8 bytes per call; these defaults may only change on development data before freeze. Same settings for every group. Provider seed unsupported/unverified; orchestration seed42, replicate1; deterministic orchestration does not guarantee deterministic generation. Observable model/fingerprint drift halts new dispatch, preserving all attempts.

Price source: [official prices](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/), [official API](https://api-docs.deepseek.com/api/create-chat-completion/), snapshot checked above. CNY per million tokens offpeak: cache-hit .02, cache-miss1, output4; peak: .04,2,8. Peak Beijing working weekdays9–12/14–18 excluding PRC holidays. Initial campaign Oct18–21 has no weekday public holiday; renew calendar snapshot before extending. Actual request timestamp/cache usage determine charge; incomplete usage stays null with reason and reserved upper cost counts against cap. Account pre-reserves peak uncached input UTF-8 byte upper bound plus4096 protocol allowance and max output, atomically including all in-flight requests; no SDK retries. <=3 total physical attempts per logical model/tool call. Internal retries and independent case attempts are distinct.

## Frozen plan and comparison

AIT22 cases×8 groups=176; DEDALE66×8=528; total704 unique rows. Both test and ablation case mappings must equal accepted Task12 selection, including original case multiplicity. No post-score reselection/replacement. Two datasets are reported separately, never pooled into one headline score.

Primary paired contrast B3–B2 on the same cases: AIT fixed six-class Macro F1, DEDALE package attack-positive F1, accompanied by answer coverage, benign FPR/correct rate, latency, model/tool calls and cost increment. B0/B1 supply references; A1–A3 explain removed capability, A4 verification effect belongs primarily to independent F8. No assumption B3 wins, no ungrounded significance stars or independence across campaign windows.

| Group | Investigation | Evidence tools | Knowledge | Verification |
|---|---|---|---|---|
| B0 | one analysis call | none | none | disabled |
| B1 | fixed seed query, one analysis | none | fixed hybrid top5 | disabled |
| B2 | one investigator, bounded loop | both | hybrid+lookup | outside main verification comparison |
| B3 | original six-role graph | both | hybrid+lookup | independent paired simulation |
| A1 | original graph | neither | hybrid+lookup | as B3 |
| A2 | original graph | both | disabled at every entry | as B3 |
| A3 | original graph | both | semantic only, no exact or keyword | as B3 |
| A4 | original graph | both | hybrid+lookup | never called, unverified |

The evidence tools are `search_security_events` and `get_alert_context`; knowledge tool `lookup_attack_technique` is retained by A1. All groups share mechanical raw-log seed, registered Evidence IDs and initial projection. Seed events are first20 in time/event order, individual event text <=2048 UTF-8 bytes, total<=24576; truncation is mechanical and disclosed. No title/label/scenario answers generate summaries/queries. B1 query concatenates first three seed summaries, truncates300 characters, top5 fixed. B2/B3 have the same tool set, scope and seed. First real seed query counts even if duplicating offline seed; repeat logical queries reuse ledger. Per round<=3, per case<=6 real logical calls including seed+lookup. A1 reserves one nontransferable first-round/global slot, so <=2 first round and<=5 total real calls; reservations reported separately, never forged as calls.

## Fixed preparation and context projection

Before any formal output, the control process exports exactly the 997 chunks parsed from the pinned public `enterprise-attack-19.2.json` and its manifest. Export checks source URI, text, metadata and 384-dimensional vectors against the registered corpus; unrelated manual/test database rows are excluded. The offline embedding model, public STIX bytes and exported rows share one read-only snapshot and tree hash. Development and formal runs use that same snapshot. No scoring material is included.

Every model role uses `bounded-context-v1`: model-facing alert event IDs are limited to the same first20 seed events. Collection scope includes only alert/time/filter/limit fields. Evidence candidates are all items up to40, otherwise first10 plus last30; packing alternates oldest/newest, clips each string to2048 UTF-8 bytes and each list to20 entries, fits evidence within60% of65536 context bytes, then restores source order. At most first5 knowledge items are packed. Mandatory remaining context exceeding the fixed byte cap fails. Per-request metadata records source/sent bytes, item counts and truncation. This mechanical rule is identical across groups and never consults gold or scores.

The official model/version/prices were rechecked on 2026-10-19 against [DeepSeek pricing](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/) and [Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/). The version and rates above remained unchanged. A control-side balance request confirmed credential availability; it did not generate model output or expand the authorized budget.

## Neutral diagnosis and immutable attempts

`Diagnosis` explicitly distinguishes attack/benign/unknown, taxonomy status, fixed mapped labels, origin, techniques, repeated stage instances, factual claims and citations. An attack outside taxonomy remains attack. Benign terminates without invented response; unknown can retry evidence once then manual review. B3 uses the original graph/checkpoint with optional internal fields, preserving public API compatibility. Snapshot is sealed after last legal analyze/reconstruct and before response/approval/simulation. Post-response observations may never update diagnostic metrics. Successful diagnosis followed by response/verification failure remains a scored diagnosis; failed diagnostic output is retained for audit but is not a successful answer.

Every row exists before execution. Attempt1 is primary unless a persisted authorization permits attempt2 exclusively for infrastructure/transport interruption. Schema exhaustion, refusal, unknown, low score are never rerun triggers. Last authorized attempt defines main row; preserve all prior failures and costs. Missing/started/failed rows never disappear. Raw output and per-call ledgers are hashed before independent scoring; later scoring/review creates separate artifacts, never overwrites output.

## Scoring rules and denominators

- DEDALE binary gold is frozen `case_is_attack`, all66 packages; event annotation coverage6563/6600 and37 related unknown events are separate. Six-class, origin, technique and stage gold masks remain N/A. Stage5/8 inventory is descriptive coverage only.
- AIT mapped six classes fixed: reconnaissance, credential_attack, webshell_upload, remote_command_execution, privilege_escalation, data_exfiltration. Fixed Macro F1 includes zero-gold/zero-predicted class F1=0; also show supported-class average and each support/prediction/correct count. Unmapped attacks are excluded only from six-class denominator, retaining binary applicability.
- Attack/benign/unknown are independent of execution status. Unknown/diagnostic failed/missing applicable rows stay in gold denominators and are not correct. Positive unanswered cases count as misses; report positive precision/recall/F1, accuracy, answer coverage, normal FPR, normal correct rate and normal unanswered rate together. Confusion gold2×prediction attack/benign/unknown/failed/missing retains every row.
- Evidence P@5 deduplicates final diagnosis citations in first-use order, pads missing citations to5 irrelevant positions. Semantic support/relevance requires actual independent human judgment; absence of relevant gold/review is N/A. Mechanical validity is current-case ownership plus trusted event/hash registry match, never semantic support. Zero citations=>validity N/A; report zero-citation report share and count.
- Stage scoring uses distinguishable frozen instances and comparable pair relations, never collapses repeated phases into a set. No comparable relations=>N/A. Existing AIT data has no reviewed technique/stage-instance contract, so those metrics remain N/A absent new independently reviewed scoring-side evidence; never infer it from model outputs.
- Source scoring honors frozen observed_source_ips/entry/time status/roles. DNS query client is not automatically external attacker. Do not manufacture origin gold.
- Missing tokens/cost/resources stay null with reason; report missing coverage. Include retry/failure/authorized-rerun costs, separately development and independent verification.

Targets are assessed separately from functional completion: AIT MacroF1>=.85, citation validity>=.95, applicable technique F1>=.80, full-population UCR<=.05 only with sufficient review; DEDALE binary positiveF1>=.85 and benignFPR<=.05 with answer coverage shown. N/A and unreviewed metrics never pass a target.

## Human review

Before final outputs, controller-side stratified seed42 sampling selects2 attacks+2 normal per dataset:8 underlying cases×8 groups=64 slots. Lock identifiers/hash before outputs and do not expose labels/list to worker. No replacement for failed, absent or claimless report. Reviewer sees blinded model/group IDs, all actual factual claims/citations, source evidence and independent scoring materials; records supported/unsupported/undetermined, basis, reviewer and timestamp. Disputes require human resolution. Uncertain judgments remain and yield bounds. Report sample UCR/semantic P@5 with dataset/group report/claim/citation/underlying-case coverage;64 reports are not64 independent cases. Single-reviewer limitation disclosed. Sample results cannot claim whole-population UCR<=5%. Unreviewed auditable claims remain incomplete, not objective inability.

The human bundle hashes the full sealed diagnostic report, including the original origin/classification and reconstructed step descriptions/times alongside canonical diagnosis facts. First-use citations across those layers share one ordered list with evidence metrics. A pre-output seed42 permutation fixes presentation order for all64 slots; missing, duplicate or changed slots invalidate import. Editing any reviewed factual field invalidates the previous judgment binding. Group IDs remain blinded and judgments remain blank until supplied by the actual reviewer.

## Independent verification experiment

For each88 cases, preregister three controlled observation conditions, giving264 paired slots/528 branch records. Clone one sealed B3 state and the same valid approved action plan into independent enabled/disabled namespaces, workers/checkpoints/ledgers. These extra branches do not replace independent A4 main rows or rewrite diagnosis. Opaque condition IDs hide truth from validator. Only typed before/after observations enter deterministic `evaluate_simulated_effect`; approval/completed simulation or same-target logs alone never establish success. For block/isolate need false→true flag; disable-account true→false; explicit observed failure=>failure; unchanged/missing/invalid provenance=>insufficient_evidence. Disabled branch=>unverified. Conditions never directly inject validation outcome.

Preserve all264 pairs including nonapplicable/not-approved/failed; compare on matched pair denominators. Minimum functional coverage:4 AIT and4 DEDALE cases each all3 conditions =24 complete pairs, without a generalization claim. Report false-success rate, explicit failure recognition, unchanged outcome distribution, actionable/approval/answer coverage and extra cost. Static and simulated evidence do not prove real containment.

## Worker boundary and freeze gates

Control plan contains gold paths/mapping; neutral WorkerRunSpec contains none. Fixed source export/image digest/locked Linux dependencies, read-only one-case agent input+knowledge+spec; no repo/.git/worktree/docs/tests/score/gold/other-case/.env mounts. Output/checkpoint and shared budget account are separate minimal writable mounts. Same PID making actual model requests performs nonce/container bound read/read-denial probe, controller inspects actual mounts then allows GO. Probe must establish legitimate read plus gold-canary/Git/other-case denial; cross-case tool/index queries rejected, including other windows. Task12 model-free evidence does not qualify. Independent scoring process cannot feed back scores.

G1 diagnosis/snapshot, G2 capabilities/budgets, G3 metrics/attempt/cost counterexamples, G4 genuine worker isolation with no critical skipped checks, G5 binding accepted data/protocol/source+lock/model/prompts/tools/knowledge/score/review/plot and human schedule. All tested source committed and actual hash frozen before final test; `--allow-final-test` mandatory and insufficient alone. No score-driven changes after freeze. G6 all704 genuinely dispatched terminal rows, necessary review complete and verification minimum met. G7 all required figures reconciled and visually checked. Missing any mandatory gate means Task13 incomplete. Regression touching common backend additionally requires real Task12 service/security checks, with critical skips counted as failure.

## Figures and delivery

Fixed F1 baseline_quality, F2 ablation_delta (ablation minus B3, percentage points), F3 evidence_quality, F4 resource_cost, F5 coverage_status, F6 binary_confusion, F8 verification_effect for each dataset; F7 six_class_f1 AIT only=15 figures. PNG300dpi width>=1800 and SVG, each CSV and caption, fixed group order, CJK font, readable N/A reasons and missing coverage. Separate execution/diagnosis panels; partial review clearly sampled. No formal data=>show honest missing state, never fake score; an empty chart cannot complete experiment delivery. Manifest binds source scores/usage/review/protocol/source/config/font and all artifact hashes. Replay `python -m evals.plots.generate` does not rescore/call models/select attempts. Report includes denominators, quality/cost tradeoff, normal false alarms, all failures/missing/unknown/N/A/unmet targets, review and single-campaign/model limitations.
