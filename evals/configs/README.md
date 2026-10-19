# Task13 controller seeds

`ait.json` and `dedale.json` are real controller seeds for the accepted 22/66-case
Task12 selections. Both use campaign `task13-campaign`, CNY100 total and CNY15
development, and deliberately have no accepted freeze. They may create plans;
formal dispatch refuses them. Their recorded source commit is the pre-Task13
baseline, not a claim that Task13 was implemented there.

After committing and testing the implementation, generate fresh controls with:

```powershell
services/backend/.venv/Scripts/python.exe -m evals.freeze --source-commit <full-tested-HEAD> --run-id task13-campaign --output data/task13/control/task13-campaign
```

The generator creates a new directory exclusively and emits deterministic
controllers and a `prepared_not_frozen` manifest. G1–G5 remain pending; isolation
and knowledge acceptance are absent. This command neither approves gates nor
calls a model. Final acceptance must bind the actual required evidence before
the generated controllers can reference a frozen manifest and its SHA256.

Generated controls remain under ignored `data/task13/control`. The source
freeze includes these committed seeds, all evaluated source/tests, dependency
files and protocol, but excludes generated freeze manifests and test scratch.
Consequently neither the source commit nor freeze hash depends on an artifact
containing its own hash. The two formal wrappers use dataset-specific default
output directories while sharing one campaign budget database in runtime config.

For a development batch, create a new controller-side selection from every
accepted AIT development row. The Task12 combined development/validation registry
has no top-level `split`; passing it directly to the planner is intentionally
refused. From the repository root, after setting `$testedCommit` to the newly
tested full HEAD:

```powershell
$task13Python = 'services/backend/.venv/Scripts/python.exe'
@'
import json, sys
from pathlib import Path
from evals.contracts import ControllerRunSpec
from evals.runners.manifest import file_hash, write_immutable_json
root = Path.cwd()
target = root / 'data/task13/control' / ('development-' + sys.argv[1])
target.mkdir(parents=True, exist_ok=False)
registry = root / '.backups/task12-readiness/data/manifests/ait-task11-dev-validation-selection.json'
rows = [row for row in json.loads(registry.read_text(encoding='utf-8'))['cases'] if row['split'] == 'development']
selection = target / 'selection.json'
write_immutable_json(selection, {'split': 'development', 'cases': rows,
    'ablation_case_ids': [row['case_id'] for row in rows],
    'source_registry_sha256': file_hash(registry)})
controller = ControllerRunSpec(run_id='task13-dev-ait', dataset='ait', split='development',
    source_commit=sys.argv[1], selection_path=str(selection), selection_sha256=file_hash(selection),
    case_root=str(root / '.backups/task12-readiness/data/ait/cases/development'))
write_immutable_json(target / 'ait-development.json', controller.model_dump(mode='json'))
print(target)
'@ | & $task13Python - $testedCommit
$developmentRoot = "data/task13/control/development-$testedCommit"
& $task13Python -m evals.runners.cli plan --config "$developmentRoot/ait-development.json" --output "$developmentRoot/plan.json"
& $task13Python -m evals.runners.cli execute --plan "$developmentRoot/plan.json" --output-root data/task13/development/attempts --runtime-config data/task13/runtime/development.json --row-limit 1
& $task13Python -m evals.runners.cli score --plan "$developmentRoot/plan.json" --output-root data/task13/development/attempts --output "$developmentRoot/scores-001.json"
```

The explicit runtime file must bind the same source commit/export, frozen Linux
dependencies, image digest, knowledge snapshot and shared campaign account, with
`phase` equal to `development`. `--row-limit 1` bounds this paid batch to one
planned group row; it does not bypass the CNY15 development allowance. Increasing
the limit resumes missing rows and never replaces a failed/completed attempt.
