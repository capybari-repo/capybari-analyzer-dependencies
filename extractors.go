package dependencies

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"

	"github.com/capybari/capybari-core/facts"
	"github.com/capybari/capybari-core/fsutil"
)

// extractors returns the SCALIBR lockfile extractors bundled in Capybari.
// Only file-based extractors for source repositories are included, which
// keeps the binary small (container/OS extractors are not needed here).
func extractors() ([]filesystem.Extractor, error) {
	cfg := &cpb.PluginConfig{MaxFileSizeBytes: 50 << 20}
	news := []func(*cpb.PluginConfig) (filesystem.Extractor, error){
		packagelockjson.New, yarnlock.New, pnpmlock.New,
		gomod.New,
		requirements.New, poetrylock.New, uvlock.New, pipfilelock.New, pdmlock.New,
		cargolock.New, composerlock.New, gemfilelock.New,
		pomxml.New, gradlelockfile.New, packageslockjson.New,
	}
	out := make([]filesystem.Extractor, 0, len(news))
	for _, n := range news {
		e, err := n(cfg)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

var lockfiles = map[string]bool{
	"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"poetry.lock": true, "uv.lock": true, "pipfile.lock": true, "pdm.lock": true,
	"cargo.lock": true, "composer.lock": true, "gemfile.lock": true, "gradle.lockfile": true, "packages.lock.json": true,
	"go.mod": true, // go.mod lists the full module graph since Go 1.17
}

func isLockfile(base string) bool { return lockfiles[strings.ToLower(base)] }

func isManifest(base string) bool {
	b := strings.ToLower(base)
	if lockfiles[b] {
		return true
	}
	switch b {
	case "package.json", "pyproject.toml", "pipfile", "gemfile", "composer.json", "cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts":
		return true
	}
	return strings.HasPrefix(b, "requirements") && strings.HasSuffix(b, ".txt")
}

type declaredDep struct {
	where string
	line  int
	dev   bool
}

type specNote struct {
	name, spec, where string
	line              int
}

// declaredSet holds what manifests declare directly, per directory+ecosystem.
type declaredSet struct {
	byDir       map[string]map[string]declaredDep // "dir|ecosystem" -> lower-cased name -> dep
	manifestEco map[string]string                 // dir -> ecosystem (for declared-only fallbacks)
	unpinned    []specNote
	vcs         []specNote
}

func (d *declaredSet) add(dir, eco, name, where string, line int, dev bool) {
	k := dir + "|" + eco
	if d.byDir[k] == nil {
		d.byDir[k] = map[string]declaredDep{}
	}
	key := strings.ToLower(name)
	if eco == "PyPI" {
		key = normPy(name)
	}
	if old, ok := d.byDir[k][key]; ok && !old.dev {
		return
	}
	d.byDir[k][key] = declaredDep{where: where, line: line, dev: dev}
}

var (
	reqLine    = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$`)
	vcsPrefix  = regexp.MustCompile(`^(git\+|git:|github:|gitlab:|bitbucket:|https?://|file:)`)
	goRequire  = regexp.MustCompile(`^\s*([^\s]+)\s+(v[^\s]+)(\s*//\s*indirect)?`)
	gemLine    = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](.*)$`)
	cargoDep   = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=`)
	pomArtifac = regexp.MustCompile(`(?s)<dependency>.*?<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(.*?)</dependency>`)
)

// declaredDeps reads direct dependency declarations from manifests.
func declaredDeps(root string, inv *facts.Inventory) *declaredSet {
	d := &declaredSet{byDir: map[string]map[string]declaredDep{}, manifestEco: map[string]string{}}
	for _, f := range inv.Files {
		if f.Kind == facts.KindVendored || f.Kind == facts.KindGenerated {
			continue
		}
		base := strings.ToLower(path.Base(f.Path))
		dir := path.Dir(f.Path)
		if !isManifest(base) {
			continue
		}
		b, _, err := fsutil.ReadFile(root, f.Path, 4<<20)
		if err != nil {
			continue
		}
		switch {
		case base == "package.json":
			var pj struct {
				Dependencies         map[string]string `json:"dependencies"`
				DevDependencies      map[string]string `json:"devDependencies"`
				OptionalDependencies map[string]string `json:"optionalDependencies"`
				PeerDependencies     map[string]string `json:"peerDependencies"`
			}
			if json.Unmarshal(b, &pj) != nil {
				continue
			}
			d.manifestEco[dir] = "npm"
			for groupDev, group := range map[bool][]map[string]string{false: {pj.Dependencies, pj.OptionalDependencies, pj.PeerDependencies}, true: {pj.DevDependencies}} {
				for _, m := range group {
					for n, spec := range m {
						d.add(dir, "npm", n, f.Path, lineOf(b, `"`+n+`"`), groupDev)
						if vcsPrefix.MatchString(spec) {
							d.vcs = append(d.vcs, specNote{n, spec, f.Path, lineOf(b, `"`+n+`"`)})
						}
					}
				}
			}
		case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
			dev := strings.Contains(base, "dev") || strings.Contains(base, "test")
			n := 0
			sc := bufio.NewScanner(bytes.NewReader(b))
			for sc.Scan() {
				n++
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if vcsPrefix.MatchString(line) || strings.HasPrefix(line, "-e ") {
					name := line
					if i := strings.Index(line, "#egg="); i >= 0 {
						name = line[i+5:]
					}
					d.vcs = append(d.vcs, specNote{name, line, f.Path, n})
					continue
				}
				if strings.HasPrefix(line, "-") {
					continue
				}
				m := reqLine.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				d.add(dir, "PyPI", m[1], f.Path, n, dev)
				spec := strings.TrimSpace(strings.SplitN(m[3], "#", 2)[0])
				if i := strings.Index(spec, ";"); i >= 0 {
					spec = strings.TrimSpace(spec[:i])
				}
				if strings.Contains(spec, " @ ") || strings.HasPrefix(spec, "@") {
					d.vcs = append(d.vcs, specNote{m[1], line, f.Path, n})
				} else if !strings.HasPrefix(spec, "==") && !strings.HasPrefix(spec, "===") {
					d.unpinned = append(d.unpinned, specNote{m[1], line, f.Path, n})
				}
			}
		case base == "go.mod":
			d.manifestEco[dir] = "Go"
			inBlock := false
			n := 0
			sc := bufio.NewScanner(bytes.NewReader(b))
			for sc.Scan() {
				n++
				line := strings.TrimSpace(sc.Text())
				switch {
				case line == "require (":
					inBlock = true
					continue
				case line == ")":
					inBlock = false
					continue
				}
				if !inBlock && !strings.HasPrefix(line, "require ") {
					continue
				}
				if m := goRequire.FindStringSubmatch(strings.TrimPrefix(line, "require ")); m != nil && m[3] == "" {
					d.add(dir, "Go", m[1], f.Path, n, false)
				}
			}
			// The main module itself is reported by the extractor as "stdlib"/"go"; mark it direct.
			d.add(dir, "Go", "stdlib", f.Path, 0, false)
		case base == "pyproject.toml":
			// PEP 621 dependencies = ["x>=1", ...] and Poetry tables.
			d.manifestEco[dir] = "PyPI"
			inPoetry := false
			n := 0
			sc := bufio.NewScanner(bytes.NewReader(b))
			inArray := false
			for sc.Scan() {
				n++
				line := strings.TrimSpace(sc.Text())
				switch {
				case strings.HasPrefix(line, "["):
					inPoetry = strings.Contains(line, "tool.poetry") && strings.Contains(line, "dependencies")
					inArray = false
					continue
				case strings.HasPrefix(line, "dependencies") && strings.Contains(line, "["):
					inArray = true
				}
				if inArray {
					for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(line, -1) {
						if m := reqLine.FindStringSubmatch(q[1]); m != nil {
							d.add(dir, "PyPI", m[1], f.Path, n, false)
						}
					}
					if strings.Contains(line, "]") {
						inArray = false
					}
				}
				if inPoetry {
					if m := cargoDep.FindStringSubmatch(line); m != nil && m[1] != "python" {
						d.add(dir, "PyPI", m[1], f.Path, n, false)
					}
				}
			}
		case base == "composer.json":
			var cj struct {
				Require    map[string]string `json:"require"`
				RequireDev map[string]string `json:"require-dev"`
			}
			if json.Unmarshal(b, &cj) == nil {
				d.manifestEco[dir] = "Packagist"
				for n := range cj.Require {
					d.add(dir, "Packagist", n, f.Path, lineOf(b, `"`+n+`"`), false)
				}
				for n := range cj.RequireDev {
					d.add(dir, "Packagist", n, f.Path, lineOf(b, `"`+n+`"`), true)
				}
			}
		case base == "gemfile":
			d.manifestEco[dir] = "RubyGems"
			for i, line := range strings.Split(string(b), "\n") {
				if m := gemLine.FindStringSubmatch(line); m != nil {
					d.add(dir, "RubyGems", m[1], f.Path, i+1, false)
					if strings.Contains(m[2], "git:") || strings.Contains(m[2], "github:") || strings.Contains(m[2], "path:") {
						d.vcs = append(d.vcs, specNote{m[1], strings.TrimSpace(line), f.Path, i + 1})
					}
				}
			}
		case base == "cargo.toml":
			d.manifestEco[dir] = "crates.io"
			section := ""
			for i, line := range strings.Split(string(b), "\n") {
				t := strings.TrimSpace(line)
				if strings.HasPrefix(t, "[") {
					section = t
					continue
				}
				if strings.HasSuffix(section, "dependencies]") {
					if m := cargoDep.FindStringSubmatch(t); m != nil {
						d.add(dir, "crates.io", m[1], f.Path, i+1, strings.Contains(section, "dev-"))
						if strings.Contains(t, "git =") || strings.Contains(t, "path =") {
							d.vcs = append(d.vcs, specNote{m[1], t, f.Path, i + 1})
						}
					}
				}
			}
		case base == "pom.xml":
			d.manifestEco[dir] = "Maven"
			for _, m := range pomArtifac.FindAllStringSubmatch(string(b), -1) {
				dev := strings.Contains(m[3], "<scope>test</scope>")
				d.add(dir, "Maven", strings.TrimSpace(m[1])+":"+strings.TrimSpace(m[2]), f.Path, 0, dev)
			}
		}
	}
	return d
}

func lineOf(b []byte, needle string) int {
	i := bytes.Index(b, []byte(needle))
	if i < 0 {
		return 0
	}
	return bytes.Count(b[:i], []byte{'\n'}) + 1
}
