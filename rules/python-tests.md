## 9) Python / Test Execution Convention

- Prefer `.venv/bin/python` and `.venv/bin/pytest` for project code, imports, and tests.
- Use host `python3` only for lightweight repository scripts that do not depend on project-only binary wheels or local venv state.
- Run targeted checks first, then broader related checks only if the targeted checks pass or if broader verification is needed for confidence.
- Do not claim a fix or success without the exact validation command and its observed result.



## Test expectations

- Aim for 100% test coverage for changed or newly added behavior.  
- When adding a new function, add corresponding tests.  
- When fixing a bug, add a regression test that fails without the fix.  
- When adding error handling, add a test that triggers the handled error path.  
- When adding conditional branches, test each meaningful branch.  
- Do not commit code that breaks existing tests.
- For CLI/report entrypoints, prefer asserting generated artifacts and content over `main()` return codes when the production path is documented to return `None`.
- Before using `pytest.raises(match=...)` for a new failure path, inspect the actual emitted message once and match the exact substring or regex that the code really raises.
