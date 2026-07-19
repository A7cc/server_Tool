package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"sync"
)

//go:embed static/* templates/*
var content embed.FS

var (
	tmplOnce sync.Once
	tmpl     *template.Template
	tmplErr  error
)

// Static returns the embedded static file system (static/ prefix stripped for http.FileServer)
func Static() http.Handler {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "static unavailable", 500)
		})
	}
	return http.FileServer(http.FS(sub))
}

// Templates parses all HTML templates once
func Templates() (*template.Template, error) {
	tmplOnce.Do(func() {
		tmpl, tmplErr = template.ParseFS(content, "templates/*.html")
	})
	return tmpl, tmplErr
}

// PageData common template data
type PageData struct {
	Title       string
	Hostname    string
	AuthEnabled bool
	RootDir     string
	Users       []string
	// files page
	RelPath string
	Parent  string
	Entries []FileEntry
}

// FileEntry directory listing row
type FileEntry struct {
	Name    string
	URL     string
	IsDir   bool
	ModTime string
	Size    string
}

// Render executes named template (file name without path, e.g. "index.html")
func Render(w http.ResponseWriter, name string, data any) error {
	t, err := Templates()
	if err != nil {
		http.Error(w, "template error: "+err.Error(), 500)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Execute the specific template file; header is defined and called via {{template "header" .}}
	return t.ExecuteTemplate(w, name, data)
}
