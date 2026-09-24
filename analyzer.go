// Package dependencies implements the Dependency Inventory & SBOM
// capability. Lockfile parsing is delegated to Google's OSV-SCALIBR
// extractors ("compose, don't clone"); this package adds direct/transitive
// classification, hygiene findings and CycloneDX output.
package dependencies

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
)

//go:embed capability.yaml
var capabilityYAML []byte

var capability = analyzer.MustParseCapability(capabilityYAML)

// Analyzer implements the capability.
type Analyzer struct{}

// New returns the capability.
func New() *Analyzer { return &Analyzer{} }

// Capability implements analyzer.Analyzer.
func (*Analyzer) Capability() analyzer.Capability { return capability }

// Applies declines when the repository has no dependency manifests.
func (*Analyzer) Applies(in *analyzer.Input) (bool, string) {
	var inv facts.Inventory
	if ok, _ := in.Evidence.Get(facts.KeyInventory, &inv); !ok {
		return false, "no inventory"
	}
	for _, f := range inv.Files {
		if isManifest(path.Base(f.Path)) {
			return true, ""
		}
	}
	return false, "no dependency manifests or lockfiles found"
}

// Analyze implements analyzer.Analyzer.
func (*Analyzer) Analyze(ctx context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	var inv facts.Inventory
	if _, err := in.Evidence.Get(facts.KeyInventory, &inv); err != nil {
		return nil, err
	}
	root := in.Target.Root
	exs, err := extractors()
	if err != nil {
		return nil, err
	}
	fsys := scalibrfs.DirFS(root)
	declared := declaredDeps(root, &inv)

	byKey := map[string]*facts.Package{}
	var manifests []facts.Manifest
	lockDirs := map[string]bool{} // dir|ecosystem with a parsed lockfile
	for _, f := range inv.Files {
		if f.Kind == facts.KindVendored || f.Kind == facts.KindGenerated {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(f.Path))
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		api := simplefileapi.New(f.Path, info)
		for _, ex := range exs {
			if !ex.FileRequired(api) {
				continue
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			m := facts.Manifest{Path: f.Path, Extractor: ex.Name(), Lockfile: isLockfile(path.Base(f.Path))}
			fh, err := os.Open(full)
			if err != nil {
				m.Error = err.Error()
				manifests = append(manifests, m)
				continue
			}
			invt, err := ex.Extract(ctx, &filesystem.ScanInput{FS: fsys, Path: f.Path, Root: root, Info: info, Reader: fh})
			fh.Close()
			if err != nil {
				m.Error = err.Error()
			}
			for _, p := range invt.Packages {
				eco := p.Ecosystem().String()
				if eco == "" {
					eco = p.PURLType
				}
				m.Ecosystem = baseEcosystem(eco)
				key := m.Ecosystem + "\x00" + p.Name + "\x00" + p.Version
				dp := byKey[key]
				if dp == nil {
					dp = &facts.Package{Name: p.Name, Version: p.Version, Ecosystem: m.Ecosystem}
					if pu := p.PURL(); pu != nil {
						dp.PURL = pu.String()
					}
					byKey[key] = dp
				}
				if !contains(dp.Locations, f.Path) {
					dp.Locations = append(dp.Locations, f.Path)
				}
				if dg, ok := p.Metadata.(interface{ DepGroups() []string }); ok {
					groups := dg.DepGroups()
					if len(groups) > 0 && allDev(groups) {
						dp.Dev = true
					}
				}
				m.Packages++
			}
			if m.Lockfile && m.Ecosystem != "" {
				lockDirs[path.Dir(f.Path)+"|"+m.Ecosystem] = true
			}
			manifests = append(manifests, m)
		}
	}

	// Declared-only dependencies (e.g. package.json without a lockfile) are
	// listed without a version so the SBOM is complete; they cannot be
	// matched against advisories.
	for dir, eco := range declared.manifestEco {
		if lockDirs[dir+"|"+eco] {
			continue
		}
		added := 0
		where := ""
		for name, d := range declared.byDir[dir+"|"+eco] {
			key := eco + "\x00" + strings.ToLower(name) + "\x00"
			exists := false
			for k := range byKey {
				if strings.HasPrefix(strings.ToLower(k), strings.ToLower(eco+"\x00"+name+"\x00")) {
					exists = true
					break
				}
			}
			if exists {
				continue
			}
			byKey[key] = &facts.Package{Name: name, Ecosystem: eco, Locations: []string{d.where}, Dev: d.dev}
			added++
			where = d.where
		}
		if added > 0 {
			manifests = append(manifests, facts.Manifest{Path: where, Ecosystem: eco, Extractor: "declared (no lockfile)", Packages: added})
		}
	}

	pkgs := make([]facts.Package, 0, len(byKey))
	for _, p := range byKey {
		// The go directive is a minimum language version; only a toolchain
		// directive pins the standard library actually used.
		if p.Ecosystem == "Go" && p.Name == "stdlib" && len(p.Locations) > 0 {
			if tc, ok := declared.goToolchain[path.Dir(p.Locations[0])]; ok {
				p.Version = tc
			} else {
				p.Version = ""
			}
		}
		dir := "."
		if len(p.Locations) > 0 {
			dir = path.Dir(p.Locations[0])
		}
		if set, ok := declared.byDir[dir+"|"+p.Ecosystem]; ok {
			_, direct := set[strings.ToLower(p.Name)]
			if !direct && p.Ecosystem == "PyPI" {
				_, direct = set[normPy(p.Name)]
			}
			d := direct
			p.Direct = &d
			if dd, ok := set[strings.ToLower(p.Name)]; ok && dd.dev {
				p.Dev = true
			}
		}
		pkgs = append(pkgs, *p)
	}
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
	sort.Slice(manifests, func(i, j int) bool { return manifests[i].Path < manifests[j].Path })
	deps := &facts.Dependencies{Packages: pkgs, Manifests: manifests}

	findings := hygiene(deps, declared)
	sbom, err := cycloneDX(in, deps)
	if err != nil {
		return nil, err
	}
	direct, eco := 0, map[string]int{}
	for _, p := range pkgs {
		if p.Direct != nil && *p.Direct {
			direct++
		}
		eco[p.Ecosystem]++
	}
	var ecos []string
	for e, n := range eco {
		ecos = append(ecos, fmt.Sprintf("%s %d", e, n))
	}
	sort.Strings(ecos)
	res := &analyzer.Result{
		Evidence:  map[string]any{facts.KeyDependencies: deps},
		Findings:  findings,
		Artifacts: []analyzer.Artifact{{Name: "sbom.cdx.json", MediaType: "application/vnd.cyclonedx+json", Data: sbom}},
		Summary:   fmt.Sprintf("%d packages (%d direct) from %d manifest(s): %s", len(pkgs), direct, len(manifests), strings.Join(ecos, ", ")),
	}
	for _, m := range manifests {
		if m.Error != "" {
			res.Limitations = append(res.Limitations, fmt.Sprintf("Could not fully parse %s: %s", m.Path, m.Error))
		}
	}
	return res, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func allDev(groups []string) bool {
	for _, g := range groups {
		if g != "dev" && g != "devDependencies" && g != "optional" {
			return false
		}
	}
	return true
}

// baseEcosystem strips OSV ecosystem suffixes ("Debian:12" -> "Debian").
func baseEcosystem(e string) string {
	if i := strings.Index(e, ":"); i > 0 {
		return e[:i]
	}
	return e
}

func normPy(n string) string {
	return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(n))
}

func hygiene(deps *facts.Dependencies, declared *declaredSet) []finding.Finding {
	var out []finding.Finding
	for _, u := range declared.unpinned {
		out = append(out, finding.Finding{
			Dimension: finding.DimDependencies, Category: "unpinned-dependency", Severity: finding.Low, Confidence: finding.ConfidenceHigh,
			Title:       "Python requirement is not pinned",
			Description: fmt.Sprintf("%s is declared as %q without an exact version or lockfile, so each install can resolve a different release.", u.name, u.spec),
			Evidence:    []finding.Evidence{{Location: finding.Location{Path: u.where, StartLine: u.line}, Snippet: u.spec}},
			Component:   u.name,
			Rule:        &finding.Rule{ID: "unpinned-requirement"},
			Remediation: &finding.Remediation{Summary: "Pin exact versions (pip-compile, uv lock or Poetry) and install from the lock.", Automatable: true},
		})
	}
	for _, v := range declared.vcs {
		out = append(out, finding.Finding{
			Dimension: finding.DimDependencies, Category: "non-registry-dependency", Severity: finding.Medium, Confidence: finding.ConfidenceHigh,
			Title:       "Dependency installed from a URL or git repository",
			Description: fmt.Sprintf("%s is fetched from %q instead of a package registry. Such dependencies bypass registry advisories and can change without a version bump.", v.name, v.spec),
			Evidence:    []finding.Evidence{{Location: finding.Location{Path: v.where, StartLine: v.line}, Snippet: v.spec}},
			Component:   v.name,
			Rule:        &finding.Rule{ID: "non-registry-dependency"},
			Remediation: &finding.Remediation{Summary: "Depend on a published, versioned release, or pin the git reference to an immutable commit and review it.", Automatable: false},
		})
	}
	versions := map[string][]string{}
	for _, p := range deps.Packages {
		if p.Version != "" && p.Ecosystem == "npm" {
			versions[p.Name] = append(versions[p.Name], p.Version)
		}
	}
	for name, vs := range versions {
		if len(vs) >= 3 {
			sort.Strings(vs)
			out = append(out, finding.Finding{
				Dimension: finding.DimDependencies, Category: "duplicate-versions", Severity: finding.Info, Confidence: finding.ConfidenceHigh,
				Title:       fmt.Sprintf("%d versions of %s installed", len(vs), name),
				Description: fmt.Sprintf("The lockfile resolves %s to %s. Duplicates increase bundle size and patching effort.", name, strings.Join(vs, ", ")),
				Component:   name,
				Rule:        &finding.Rule{ID: "duplicate-versions"},
				Remediation: &finding.Remediation{Summary: "Align dependents on one version (npm dedupe / overrides).", Automatable: true},
			})
		}
	}
	return out
}
