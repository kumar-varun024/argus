import sys
import subprocess
import os
from typing import Optional
from argus.benchmark.leaderboard.models import RegressionReport, Classification

class CIIntegration:
    
    @staticmethod
    def get_commit_sha() -> str:
        """Extracts the commit SHA from the environment or local git repo."""
        # 1. Check CI env vars first
        for env_var in ["ARGUS_COMMIT_SHA", "GITHUB_SHA", "GIT_COMMIT", "CI_COMMIT_SHA"]:
            if env_var in os.environ:
                return os.environ[env_var]
                
        # 2. Fallback to local git
        try:
            result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return "unknown-commit"
            
    @staticmethod
    def handle_regression_exit(report: RegressionReport, fail_on_regression: bool = True):
        """Outputs CI-friendly format and exits with appropriate status code."""
        
        print(f"::group::Regression Report")
        print(f"Overall Status: {report.overall_status}")
        
        if report.incompatible_metrics:
            print("Status: INCOMPATIBLE")
            print("Reason: Baseline and current dataset/version mismatch.")
            print("::endgroup::")
            if fail_on_regression:
                sys.exit(2) # Special exit code for incompatibility
            return
            
        if report.improvements:
            print("Improvements:")
            for imp in report.improvements:
                print(f"  - {imp.metric_name} improved by {abs(imp.percentage_difference):.2f}%")
                
        if report.regressions:
            print("Regressions:")
            for reg in report.regressions:
                print(f"  - {reg.metric_name} regressed by {abs(reg.percentage_difference):.2f}%")
                
        print("::endgroup::")
        
        if fail_on_regression and report.overall_status in (Classification.REGRESSED, Classification.SIGNIFICANTLY_REGRESSED):
            print(f"::error::Argus benchmark detected {report.overall_status.value}. Failing CI.")
            sys.exit(1)
            
        sys.exit(0)
