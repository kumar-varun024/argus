# Integrating Argus Benchmarks with GitHub Actions

Argus provides a robust Leaderboard and Regression Detection system natively out-of-the-box. This ensures that PRs are evaluated strictly against their performance rather than just feature count.

To integrate this into GitHub Actions, create a workflow file (e.g., `.github/workflows/benchmark.yml`) with the following structure:

```yaml
name: Benchmark Regression Check

on:
  pull_request:
    branches:
      - main
  push:
    branches:
      - main

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0 # Required for git rev-parse HEAD

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install Dependencies
        run: |
          pip install -r requirements.txt
          pip install -e .

      - name: Run Unit Tests
        run: pytest tests/

      - name: Run Benchmark Suite
        # Runs the suite and evaluates it. 
        # In a real CI environment, you'd likely restore the `.argus/leaderboard.json` cache first.
        run: argus benchmark run --suite

      - name: Check for Regressions
        # Compare the newly run benchmark against the previous baseline.
        # This will exit 1 if a significant regression (e.g., Overall Score drop > 2%) is detected.
        run: argus benchmark regression --fail-on-regression
        env:
          ARGUS_COMMIT_SHA: ${{ github.sha }}
```

## How It Works
1. `argus benchmark run --suite` will generate an `EvaluationResult` and (if configured in `runner.py`) log it to the leaderboard registry.
2. `argus benchmark regression` will resolve the most recent valid baseline for the datasets evaluated and compare it with the current run.
3. If an incompatible change is detected (e.g., the benchmark dataset schema changed), it fails the CI by returning a `2` exit code.
4. If a regression > configured threshold is detected, it returns a `1` exit code to block the PR.
5. If the result is stable or improved, it returns a `0` exit code.

## Configurable Thresholds
You can override the thresholds by injecting environment variables:
- `ARGUS_THRESHOLD_OVERALL_SCORE=1.5`
- `ARGUS_THRESHOLD_INVESTIGATION_QUALITY=2.0`
- `ARGUS_THRESHOLD_RUNTIME_INCREASE=15.0`
