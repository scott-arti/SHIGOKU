## File Upload Procedure

If the task is related to "File Upload" or the tags contain `file_upload`, `upload`, or `rce_candidate` AND the primary target looks like an upload page, follow these steps:

1. **FIRST**: Call `fetch_page_content(url='{{ target }}')` to analyze the HTML of the upload page.
2. **SECOND**: From the HTML, identify:
   - The form `action` URL (endpoint that receives the upload)
   - The file input `name` attribute (e.g., `<input type="file" name="uploaded">`)
   - Other required inputs: submit buttons, CSRF tokens, hidden fields
3. **THIRD**: Call `run_file_upload_check` with:
   - `url`: the form `action` URL
   - `param_name`: the file input `name`
   - `extra_params`: all other non-file input fields (e.g., `{"submit": "Upload", "csrf_token": "..."}`)

Do NOT call `run_file_upload_check` without first fetching the page content and identifying parameters.
Do NOT use empty dictionary for `extra_params` if the form has other inputs.
