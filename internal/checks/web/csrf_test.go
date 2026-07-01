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
	"testing"

	"github.com/osintph/suri/internal/checks"
	"github.com/osintph/suri/internal/crawler"
	internalhttp "github.com/osintph/suri/internal/http"
	"github.com/osintph/suri/internal/scope"
)

func csrfTarget() *checks.Target {
	sc := &scope.Scope{Hostnames: []string{"127.0.0.1"}, IPs: []string{"127.0.0.1"}}
	return &checks.Target{
		Inventory: &crawler.Inventory{},
		Scope:     sc,
		HTTP:      internalhttp.New(sc),
	}
}

func TestFormWithoutCSRFTokenEmitsFinding(t *testing.T) {
	target := csrfTarget()
	target.Inventory.Forms = []*crawler.Form{
		{
			PageURL: "http://example.com/login",
			Action:  "http://example.com/login",
			Method:  "POST",
			Fields:  []string{"username", "password"},
		},
	}

	ck := &CSRFCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected CSRF finding for POST form without token, got 0")
	}
	if len(findings) > 0 && findings[0].CheckID != "web.forms.missing-csrf" {
		t.Errorf("unexpected CheckID %q", findings[0].CheckID)
	}
}

func TestFormWithCSRFTokenNoFinding(t *testing.T) {
	target := csrfTarget()
	target.Inventory.Forms = []*crawler.Form{
		{
			PageURL: "http://example.com/login",
			Action:  "http://example.com/login",
			Method:  "POST",
			Fields:  []string{"username", "password", "authenticity_token"},
		},
	}

	ck := &CSRFCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for form with CSRF token, got %d", len(findings))
	}
}

func TestGetFormSkipped(t *testing.T) {
	target := csrfTarget()
	target.Inventory.Forms = []*crawler.Form{
		{
			PageURL: "http://example.com/search",
			Action:  "http://example.com/search",
			Method:  "GET",
			Fields:  []string{"q"},
		},
	}

	ck := &CSRFCheck{}
	findings, err := ck.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("GET forms should be skipped, got %d findings", len(findings))
	}
}
