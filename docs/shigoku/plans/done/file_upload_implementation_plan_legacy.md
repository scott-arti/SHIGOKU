---
task_id: SGK-2026-0216
doc_type: plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# File Upload Vulnerability Scanner Implementation Plan

## Goal Description

Implement a specialized scanner for detecting Unrestricted File Upload vulnerabilities, specifically targeting RCE (Remote Code Execution) via WebShell upload.
Currently, `ReconPipeline` identifies upload endpoints but lacks a dedicated scanner to exploit them, falling back to a generic injection scan or race condition check.

## User Review Required

> [!IMPORTANT]
> This feature introduces active exploitation attempts (uploading files). While safety measures (using benign filenames, attempting cleanup) are included, it carries a risk of leaving files on the target server if cleanup fails.
> **Confirm if this acceptable for the target scope.**

## Proposed Changes

### Core Attack Module

#### [NEW] [file_upload_tester.py](file:///home/bbb/Documents/App/Shigoku/src/core/attack/file_upload_tester.py)

- Implement `FileUploadTester` class.
- Methods:
  - `test_upload()`: Main entry point.
  - `_generate_payloads()`: Generate payloads with various extensions/MIMEs.
  - `_verify_upload()`: Check if uploaded file is accessible and executable.

### Logic Swarm

#### [NEW] [file_upload.py](file:///home/bbb/Documents/App/Shigoku/src/core/agents/swarm/logic/file_upload.py)

- Implement `FileUploadSpecialist` class inheriting from `Specialist`.
- Use `FileUploadTester` to execute scans.
- Parse results into `Finding` objects with `Severity.CRITICAL` for RCE.

#### [MODIFY] [manager.py](file:///home/bbb/Documents/App/Shigoku/src/core/agents/swarm/logic/manager.py)

- Import and register `FileUploadSpecialist` in `LogicSwarm`.

### Recon Pipeline

#### [MODIFY] [pipeline.py](file:///home/bbb/Documents/App/Shigoku/src/recon/pipeline.py)

- Update `_generate_tasks_for_tagged_urls` to route `upload` category tasks to `LogicSwarm` (instead of `InjectionManagerAgent`).
- Ensure `LogicSwarm` is initialized and used correctly.

## Verification Plan

### Automated Tests

#### [NEW] [test_file_upload.py](file:///home/bbb/Documents/App/Shigoku/tests/core/attack/test_file_upload.py)

- **Test Case 1**: Successful upload of benign file.
- **Test Case 2**: Blocked extension (simulate WAF/Filter).
- **Test Case 3**: Bypass success (e.g. `.php.jpg`).
- **Test Case 4**: RCE verification (mocking response content).

Command:

```bash
pytest tests/core/attack/test_file_upload.py
```

### Manual Verification (E2E)

1. **Target**: Localhost DVWA (`http://localhost:4280/vulnerabilities/upload/`)
2. **Procedure**:
   - Run the pipeline or specific task for the upload endpoint.
   - Check if `Finding` with `Severity.CRITICAL` is reported.
   - Verify that a file was uploaded (check DVWA `hackable/uploads/` directory).

Command:

```bash
# Run specific scan task against DVWA upload endpoint
python3 -m src.tools.debug_cli scan --target http://localhost:4280/vulnerabilities/upload/ --type upload
```

(Note: `debug_cli` might need update or use `master_conductor` directly via script)
