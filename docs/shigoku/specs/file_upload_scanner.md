---
task_id: SGK-2026-0118
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# File Upload Vulnerability Scanner Specification

## Overview

Webアプリケーションのファイルアップロード機能における脆弱性（Unrestricted File Upload）を検出するためのスキャナーを実装する。
特に、DVWA (Damn Vulnerable Web App) などの演習環境や、実際の診断において、WebShellの配置によるRCE (Remote Code Execution) の可能性を検証することを目的とする。

## Scope

- **Agent**: `LogicSwarm` (Business Logic Vulnerabilities)
- **Specialist**: `FileUploadSpecialist` (New)
- **Attack Module**: `src/core/attack/file_upload_tester.py` (New)
- **Input**:
  - Target URL (Upload Form Endpoint)
  - Parameters (Optional: file param name, etc. defaults to 'uploaded', 'file', etc.)
- **Output**:
  - `Finding` with `Severity.CRITICAL` if RCE is possible.

## Detailed Logic

### 1. Payload Generation

以下のパターンで検証用ファイル（WebShell等）を生成・試行する。

- **Basis**: 単純なPHPコード `<?php echo "VULN_CONFIRMED"; system($_GET['c']); ?>`
- **Extensions**:
  - `.php` (Basic)
  - `.php.jpg`, `.php.png` (Double Extension)
  - `.php5`, `.phtml` (Alternative Extensions)
  - `.htaccess` (Apache Config Override - if possible)
- **MIME Types**:
  - `application/x-php`
  - `image/jpeg`, `image/png` (Bypass Content-Type Check)
- **Magic Bytes**:
  - JPEG Header (`\xFF\xD8\xFF...`) + PHP Code (Bypass Content Check)

### 2. Execution Flow

1. **Initial Probe**: 通常の無害な画像ファイルをアップロードし、正常系の挙動（保存パス、レスポンス形式）を学習する。
2. **Attack Phase**: 上記ペイロードを順次送信する。
3. **Verification Phase**: アップロードされたファイルにアクセスし、PHPコードが実行されるか確認する。
   - レスポンスボディに `VULN_CONFIRMED` が含まれれば脆弱性と判定。
   - アップロード先パスの推測には、Initial Probeのレスポンスや、一般的なパス (`/uploads/`, `./`, `../uploads/` 等) を使用する。

## Constraints & Safety

- **IsAggressive**: このスキャンは `is_aggressive=True` の場合のみ実行されるべきである（ファイルの書き込みを伴うため）。
- **Cleanup**: 可能な限り、テスト後にアップロードしたファイルを削除する（ただしWebShellが動作しない場合、削除も難しい場合がある）。
- **Rate Limit**: 連続的なアップロードはDoSになる可能性があるため、適切なインターバルを設ける。

## Integration

- `recon/pipeline.py` において、`upload` タグが検知されたURLに対して、`LogicSwarm` 経由で本Specialistを実行するようルーティングを変更する。
