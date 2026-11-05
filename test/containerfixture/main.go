// Local-only fixture for the container browser smoke job. Never contacts other hosts.
package main

import (
	"fmt"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><body>"+r.URL.Query().Get("q")+"</body></html>")
	})
	server := &http.Server{Addr: "127.0.0.1:18080", Handler: mux}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
