# capybari-analyzer-dependencies

**Capybari Source Intelligence: Dependency Inventory & SBOM: what does this depend on?**

- Direct and transitive dependencies from lockfiles and manifests: npm/yarn/pnpm, Go modules, pip requirements, Poetry, uv, Pipenv, PDM, Cargo, Composer, Bundler, Maven `pom.xml`, Gradle lockfiles and NuGet `packages.lock.json`
- Classification: direct vs transitive, dev vs runtime
- A **CycloneDX 1.6 SBOM** (`sbom.cdx.json`) with reproducible output
- Hygiene findings: unpinned Python requirements, dependencies fetched from git or URLs, npm packages installed in three or more versions

Lockfile parsing uses Google's [OSV-SCALIBR](https://github.com/google/osv-scalibr) extractors (Apache-2.0), imported as a library. Only the source-lockfile extractors are linked in, which keeps the binary small.

| | |
|---|---|
| Requires | `inventory` |
| Provides | `dependencies` evidence, `sbom.cdx.json` artifact |
| Scores | Dependency Hygiene |
| Network / AI | none / none |

```bash
go run ./cmd/capybari-dependencies ./path/to/project
```

## License

Apache-2.0
