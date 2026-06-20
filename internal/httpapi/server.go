package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/NUS-MTech-Capstone/incident-agent/api"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/service"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/store"
)

type userKey struct{}

type User struct {
	Subject string
	Email   string
}

type Server struct {
	service *service.Service
	mux     *http.ServeMux
	pages   *template.Template
}

func New(svc *service.Service) *Server {
	s := &Server{
		service: svc,
		mux:     http.NewServeMux(),
		pages:   template.Must(template.New("pages").Parse(pageTemplates)),
	}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /openapi.yaml", serveYAML(api.OpenAPI))
	s.mux.Handle("GET /incidents", cognito(http.HandlerFunc(s.list)))
	s.mux.Handle("GET /incidents/", cognito(http.HandlerFunc(s.detail)))
	s.mux.Handle("POST /incidents/", cognito(http.HandlerFunc(s.action)))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	incidents, err := s.service.List(r.Context())
	if err != nil {
		http.Error(w, "unable to list incidents", http.StatusInternalServerError)
		return
	}
	user, _ := r.Context().Value(userKey{}).(User)
	s.render(w, "list", map[string]any{"Incidents": incidents, "User": user})
}

func (s *Server) detail(w http.ResponseWriter, r *http.Request) {
	id, action := parseIncidentPath(r.URL.Path)
	if id == "" || action != "" {
		http.NotFound(w, r)
		return
	}
	incident, err := s.service.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "unable to load incident", http.StatusInternalServerError)
		return
	}
	user, _ := r.Context().Value(userKey{}).(User)
	s.render(w, "detail", map[string]any{"Incident": incident, "User": user})
}

func (s *Server) action(w http.ResponseWriter, r *http.Request) {
	id, action := parseIncidentPath(r.URL.Path)
	if id == "" || (action != "approve" && action != "reject") {
		http.NotFound(w, r)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-site decisions are not allowed", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	planHash := r.FormValue("planHash")
	user, ok := r.Context().Value(userKey{}).(User)
	if !ok || planHash == "" {
		http.Error(w, "identity and plan hash are required", http.StatusBadRequest)
		return
	}
	var err error
	if action == "approve" {
		err = s.service.Approve(r.Context(), id, planHash, user.Subject)
	} else {
		err = s.service.Reject(r.Context(), id, planHash, user.Subject)
	}
	if errors.Is(err, store.ErrConflict) {
		http.Error(w, "incident changed; reload before deciding", http.StatusConflict)
		return
	}
	if err != nil {
		log.Printf("incident decision failed incidentId=%q action=%q error=%q", id, action, err.Error()) // #nosec G706 -- id/action are constrained and %q escapes control characters.
		http.Error(w, "unable to record decision", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/incidents/"+url.PathEscape(id), http.StatusSeeOther)
}

func sameOrigin(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Host != "" && strings.EqualFold(parsed.Host, r.Host)
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render incident page failed: %v", err)
	}
}

func cognito(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := userFromHeader(r.Header.Get("x-amzn-oidc-data"))
		if err != nil {
			http.Error(w, "missing or invalid Cognito identity", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
	})
}

func userFromHeader(token string) (User, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return User{}, errors.New("invalid JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return User{}, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return User{}, err
	}
	subject, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	if subject == "" {
		return User{}, errors.New("sub is required")
	}
	return User{Subject: subject, Email: email}, nil
}

func parseIncidentPath(path string) (string, string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || parts[0] != "incidents" {
		return "", ""
	}
	if !validPathID(parts[1]) {
		return "", ""
	}
	if len(parts) == 2 {
		return parts[1], ""
	}
	return parts[1], parts[2]
}

func validPathID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func serveYAML(contents []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(contents)
	}
}

const pageTemplates = `
{{define "head"}}<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DenDenMushi Incidents</title><style>
body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}
table{border-collapse:collapse;width:100%}th,td{padding:.65rem;border-bottom:1px solid #ddd;text-align:left}
.state{font-weight:700}.card{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
pre{white-space:pre-wrap;background:#f6f8fa;padding:1rem;overflow:auto}button{padding:.6rem 1rem;margin-right:.5rem}
.danger{background:#a61b1b;color:white;border:0}.approve{background:#176b36;color:white;border:0}
a{color:#175ea8}</style></head><body>{{end}}
{{define "list"}}{{template "head" .}}<h1>Incidents</h1><p>Signed in as {{.User.Email}}</p>
<table><thead><tr><th>Created</th><th>Alarm</th><th>Host</th><th>State</th></tr></thead><tbody>
{{range .Incidents}}<tr><td>{{.CreatedAt}}</td><td><a href="/incidents/{{.ID}}">{{.AlarmName}}</a></td><td>{{.HostID}}</td><td class="state">{{.State}}</td></tr>{{else}}<tr><td colspan="4">No incidents</td></tr>{{end}}
</tbody></table></body></html>{{end}}
{{define "detail"}}{{template "head" .}}<p><a href="/incidents">Back</a></p><h1>{{.Incident.AlarmName}}</h1>
<div class="card"><b>State:</b> {{.Incident.State}}<br><b>Host:</b> {{.Incident.HostID}}<br><b>Reason:</b> {{.Incident.Reason}}</div>
{{if .Incident.Plan.Summary}}<div class="card"><h2>Proposed plan</h2><p><b>{{.Incident.Plan.Summary}}</b></p><p>{{.Incident.Plan.Rationale}}</p>
{{range .Incident.Plan.Actions}}<p><code>{{.OperationID}}</code>: {{.Reason}}</p>{{end}}</div>{{end}}
{{if eq .Incident.State "AWAITING_APPROVAL"}}<form method="post" action="/incidents/{{.Incident.ID}}/approve">
<input type="hidden" name="planHash" value="{{.Incident.PlanHash}}"><button class="approve" type="submit">Approve exact plan</button></form>
<form method="post" action="/incidents/{{.Incident.ID}}/reject"><input type="hidden" name="planHash" value="{{.Incident.PlanHash}}">
<button class="danger" type="submit">Reject</button></form>{{end}}
{{if .Incident.Evidence}}<h2>Evidence</h2>{{range .Incident.Evidence}}<div class="card"><b>{{.OperationID}}</b> (exit {{.ExitCode}})
<pre>{{.Stdout}}{{.Stderr}}</pre></div>{{end}}{{end}}
{{if .Incident.Report}}<h2>Report</h2><pre>{{.Incident.Report}}</pre>{{end}}
{{if .Incident.ErrorMessage}}<h2>Error</h2><pre>{{.Incident.ErrorMessage}}</pre>{{end}}</body></html>{{end}}`
