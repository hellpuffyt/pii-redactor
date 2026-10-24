# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's advisory form:
<https://github.com/hellpuffyt/pii-redactor/security/advisories/new>

Do not open a public issue for a vulnerability, and **never include real
personal data** in a report — a synthetic reproduction (e.g. `example.com`
addresses, published test card numbers) is all that is needed.

Examples of what counts as a security issue here:

- a detected value appearing in diagnostic output, dry-run reports, error
  messages, or anywhere other than the configured policy action;
- the redacted output containing a value the README says is redacted;
- the mapping file being written somewhere other than `--mapping-file`, or
  with broader permissions than documented;
- a crafted input that makes the tool hang or exhaust memory.

A detector simply missing an unusual format is a detection-quality bug; a
normal issue with a synthetic example is fine for those.

## Supported versions

Only the latest release on the default branch receives fixes.
