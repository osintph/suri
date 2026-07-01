// Suri, a web application security scanner for authorized VAPT engagements.
// Copyright (C) 2026 OSINT-PH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package web

import (
	"context"
	"fmt"
	"strings"

	"github.com/osintph/suri/internal/checks"
)

// csrfTokenFields is the set of input field names that indicate a CSRF token.
var csrfTokenFields = map[string]bool{
	"authenticity_token": true,
	"csrf_token":         true,
	"_csrf":              true,
	"_token":             true,
	"user_token":         true,
	"csrfToken":          true,
}

// CSRFCheck inspects POST forms in the inventory for missing CSRF tokens.
type CSRFCheck struct{}

func (c *CSRFCheck) ID() string                { return "web.forms.missing-csrf" }
func (c *CSRFCheck) Name() string              { return "Missing CSRF Token on POST Form" }
func (c *CSRFCheck) Severity() checks.Severity { return checks.SeverityLow }
func (c *CSRFCheck) Category() checks.Category { return checks.CategoryWeb }

func (c *CSRFCheck) Run(ctx context.Context, target *checks.Target) ([]*checks.Finding, error) {
	if target.Inventory == nil {
		return nil, nil
	}
	var findings []*checks.Finding
	seen := make(map[string]bool)

	for _, form := range target.Inventory.Forms {
		if strings.ToUpper(form.Method) != "POST" {
			continue
		}
		hasToken := false
		for _, field := range form.Fields {
			if csrfTokenFields[field] {
				hasToken = true
				break
			}
		}
		if hasToken {
			continue
		}
		key := form.Action + "|" + form.PageURL
		if seen[key] {
			continue
		}
		seen[key] = true

		actionURL := form.Action
		if actionURL == "" {
			actionURL = form.PageURL
		}
		findings = append(findings, &checks.Finding{
			CheckID:    c.ID(),
			Severity:   checks.SeverityLow,
			Confidence: checks.ConfidenceFirm,
			Title:      fmt.Sprintf("POST form at %s lacks a CSRF token field", actionURL),
			Description: fmt.Sprintf(
				"The POST form at %s (discovered on %s) does not contain a recognized CSRF token "+
					"field. Without a per-session unpredictable token, the form may be vulnerable "+
					"to cross-site request forgery attacks.",
				actionURL, form.PageURL,
			),
			URL:   actionURL,
			CWE:   "CWE-352",
			OWASP: "A01:2021",
		})
	}
	return findings, nil
}
