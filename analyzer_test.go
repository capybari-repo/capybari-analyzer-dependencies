package dependencies_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	dependencies "github.com/capybari/capybari-analyzer-dependencies"
	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/analyzertest"
	"github.com/capybari/capybari-core/facts"
	"github.com/capybari/capybari-schemas"
	"gopkg.in/yaml.v3"
)

const fixtures = "../capybari-fixtures"

func TestCapabilityMetadata(t *testing.T) {
	b, err := os.ReadFile("capability.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := analyzer.ParseCapability(b); err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateValue("capability.schema.json", doc); err != nil {
		t.Fatal(err)
	}
}

type row struct {
	Eco, Name, Version string
	Direct             *bool
	Dev                bool
}

func TestFixtures(t *testing.T) {
	for _, name := range []string{"node-express-legacy", "python-flask-app", "go-service"} {
		t.Run(name, func(t *testing.T) {
			r, st := analyzertest.RunState(t, dependencies.New(), analyzertest.Repo(t, filepath.Join(fixtures, name)), analyzertest.Options{})
			deps := analyzertest.Fact[facts.Dependencies](t, r, facts.KeyDependencies)
			var rows []row
			for _, p := range deps.Packages {
				rows = append(rows, row{p.Ecosystem, p.Name, p.Version, p.Direct, p.Dev})
			}
			analyzertest.Golden(t, name, rows)

			run := st.Runs["dependencies"]
			if len(run.Artifacts) != 1 || run.Artifacts[0].Name != "sbom.cdx.json" {
				t.Fatalf("artifacts: %+v", run.Artifacts)
			}
			var bom map[string]any
			if err := json.Unmarshal(run.Artifacts[0].Data, &bom); err != nil {
				t.Fatal(err)
			}
			if bom["bomFormat"] != "CycloneDX" || len(bom["components"].([]any)) != len(deps.Packages) {
				t.Fatalf("bad SBOM: %v", bom["bomFormat"])
			}
		})
	}
}

func TestHygieneFindings(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask>=2.0\nrequests==2.31.0\ngit+https://github.com/org/lib.git#egg=lib\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"left-pad":"github:org/left-pad"}}`), 0o644)
	r := analyzertest.Run(t, dependencies.New(), analyzertest.Repo(t, dir), analyzertest.Options{})
	got := map[string]int{}
	for _, f := range r.Findings {
		got[f.Rule.ID]++
	}
	if got["unpinned-requirement"] != 1 || got["non-registry-dependency"] != 2 {
		t.Fatalf("findings: %v", got)
	}
}
