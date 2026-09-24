package dependencies

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/facts"
)

// Minimal CycloneDX 1.6 JSON model (https://cyclonedx.org/docs/1.6/json/).

type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
	Dependencies []cdxDep       `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     cdxTools     `json:"tools"`
	Component cdxComponent `json:"component"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	Scope      string        `json:"scope,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// cycloneDX renders the dependency inventory as a CycloneDX 1.6 SBOM. The
// serial number is derived from the content so identical inputs give an
// identical document (reproducible output).
func cycloneDX(in *analyzer.Input, deps *facts.Dependencies) ([]byte, error) {
	rootRef := "root:" + in.Target.Display
	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: in.Now().UTC().Format("2006-01-02T15:04:05Z"),
			Tools: cdxTools{Components: []cdxComponent{
				{Type: "application", Name: "capybari-analyzer-dependencies", Version: capability.Version},
				{Type: "library", Name: "osv-scalibr", Version: capability.Engines[0].Version},
			}},
			Component: cdxComponent{Type: "application", BOMRef: rootRef, Name: in.Target.Display},
		},
		Components: []cdxComponent{},
	}
	var direct []string
	seen := map[string]bool{}
	for _, p := range deps.Packages {
		ref := p.PURL
		if ref == "" {
			ref = fmt.Sprintf("%s:%s@%s", strings.ToLower(p.Ecosystem), p.Name, p.Version)
		}
		if seen[ref] {
			continue
		}
		seen[ref] = true
		c := cdxComponent{Type: "library", BOMRef: ref, Name: p.Name, Version: p.Version, PURL: p.PURL, Scope: "required"}
		if p.Dev {
			c.Scope = "optional"
		}
		c.Properties = append(c.Properties, cdxProperty{Name: "capybari:ecosystem", Value: p.Ecosystem})
		for _, l := range p.Locations {
			c.Properties = append(c.Properties, cdxProperty{Name: "capybari:location", Value: l})
		}
		if p.Direct != nil {
			c.Properties = append(c.Properties, cdxProperty{Name: "capybari:direct", Value: fmt.Sprint(*p.Direct)})
			if *p.Direct {
				direct = append(direct, ref)
			}
		}
		bom.Components = append(bom.Components, c)
	}
	bom.Dependencies = []cdxDep{{Ref: rootRef, DependsOn: append([]string{}, direct...)}}
	body, err := json.Marshal(bom.Components)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte(rootRef), body...))
	h := hex.EncodeToString(sum[:16])
	bom.SerialNumber = fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
	return json.MarshalIndent(bom, "", "  ")
}
