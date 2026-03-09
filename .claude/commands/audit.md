Audit a dstack TEE application for DevProof (ERC-733) compliance.

Usage: /audit <repo_url> <website_url>

Arguments: $ARGUMENTS

Steps:
1. Parse the two arguments from $ARGUMENTS. The first is a GitHub repo URL, the second is the Phala Cloud app URL.
2. Run the audit pipeline: `python -m dstack_audit <repo_url> <website_url> -v`
3. Read the output (the Markdown report printed to stdout).
4. Provide a prose summary including:
   - The **Stage rating** (0 = Ruggable, 1 = DevProof)
   - Key findings, especially any CRITICAL ones
   - For each critical finding, explain the **attack vector** clearly: what could a malicious developer do?
   - The Stage 1 checklist status
5. If the stage is 0, explain what would need to change for Stage 1.
6. End with a clear **verdict**: "Safe to interact with" or "NOT safe — here's why".
