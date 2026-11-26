# Inspect Package Registry Egress to Block Typosquatting and Unpinned Supply-Chain Installs

Allowing unrestricted `GET` access to `registry.npmjs.org`, `pypi.org`, or `files.pythonhosted.org` lets compromised or hallucinating agents download typosquatted packages (e.g., `lodahs`, `reqeusts`) or arbitrary unpinned transitive packages. `PackageRegistryGuard` inspects package identifiers in every outbound HTTPS MITM request inside the **Egress Firewall**, checking explicit `deniedPackages` / `allowedPackages` policies, repository manifests/lockfiles (`package.json`, `package-lock.json`, `pnpm-lock.yaml`, `requirements.txt`), and Damerau-Levenshtein distance-1 typosquatting targets.

## Consequences

- Typosquats of popular npm/PyPI packages, built-in malicious package names, `@scope/*` denylist matches, and unpinned dependencies (when `enforceLockfile: true`) are blocked at the **Egress Firewall** with `HTTP 403` and recorded as `SUPPLY_CHAIN_PACKAGE_BLOCKED` events.
- Repository owners declare fine-grained registry rules inside `aegis.policy.json` under `packagePolicy` without loosening kernel isolation or disabling registry access for pinned builds.
