# InfraGuard Sample Test Pack

Synthetic Terraform HCL fixtures for local testing of InfraGuard. No cloud credentials are included, and nothing in this pack creates or changes real cloud resources.

## How to use
1. Extract this ZIP.
2. Open InfraGuard locally.
3. Create separate scans and upload each `.tf` fixture using the Terraform/HCL option.
4. Compare the scan findings with `EXPECTED_RESULTS.md`.
5. If your UI/API supports only a subset of the resource types or rules below, record them as `UNSUPPORTED` or `NOT_EVALUATED` rather than treating them as secure.

## Important
These are input fixtures, not a guarantee that every rule is implemented by your current build. Expected outcomes are conditional on the corresponding provider parser and policy being implemented. Terraform files are intentionally not accompanied by real provider credentials, state files, modules, or deployment instructions.
