# Methodology: Dependency Inventory & SBOM

## Extraction

For every inventoried file (vendored and generated files excluded), each bundled OSV-SCALIBR extractor decides whether the file is relevant and extracts packages with name, version, ecosystem and PURL. Packages seen in several files are merged, and every location is kept.

Manifests that have no lockfile next to them (for example a `package.json` alone) contribute their declared dependencies **without a version**. The SBOM stays complete, but those packages cannot be matched against advisories. The fingerprint capability reports the missing lockfile.

## Direct vs transitive

A package is **direct** when the manifest in the same directory declares it: `package.json` dependency groups, `go.mod` requires without `// indirect`, requirements files, `pyproject.toml`, `composer.json`, `Gemfile`, `Cargo.toml` or `pom.xml`. **Dev** dependencies come from `devDependencies`, `require-dev`, `[dev-dependencies]`, test scope, npm lockfile dev groups and requirements files whose name contains `dev` or `test`.

## Findings

| Rule | Severity | Confidence | Trigger |
|---|---|---|---|
| `unpinned-requirement` | low | high | requirements line without `==` |
| `non-registry-dependency` | medium | high | git/URL/path dependency (npm `github:`/`git+`, pip `git+`/`@ url`, Gemfile `git:`, Cargo `git =`) |
| `duplicate-versions` | info | high | the same npm package resolved to ≥ 3 versions |

## SBOM

CycloneDX 1.6 JSON. Dev dependencies get `scope: optional`. The serial number is derived from content, so identical inputs produce identical files, which suits CI diffing.
