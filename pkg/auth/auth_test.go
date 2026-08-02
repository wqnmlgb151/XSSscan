package auth

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAuthenticateSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		user := r.FormValue("username")
		pass := r.FormValue("password")
		if user == "admin" && pass == "secret" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "authtoken123"})
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Welcome, admin!"))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid password"))
		}
	}))
	defer server.Close()

	client := &http.Client{}
	jar, _ := cookiejar.New(&cookiejar.Options{})
	client.Jar = jar

	cfg := LoginConfig{
		LoginURL:  server.URL + "/login",
		Username:  "admin",
		Password:  "secret",
		UserField: "username",
		PassField: "password",
	}

	err := Authenticate(client, cfg)
	if err != nil {
		t.Fatalf("Expected successful login, got error: %v", err)
	}

	// Verify cookie was set
	u, _ := url.Parse(server.URL)
	if len(jar.Cookies(u)) == 0 {
		t.Error("Expected session cookie to be set after login")
	}
}

func TestAuthenticateFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid password"))
	}))
	defer server.Close()

	client := &http.Client{}
	jar, _ := cookiejar.New(&cookiejar.Options{})
	client.Jar = jar

	cfg := LoginConfig{
		LoginURL:  server.URL + "/login",
		Username:  "admin",
		Password:  "wrong",
		UserField: "username",
		PassField: "password",
	}

	err := Authenticate(client, cfg)
	if err == nil {
		t.Error("Expected login failure, but got success")
	}
}

func TestAuthenticateDefaultFieldNames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("username") != "" && r.FormValue("password") != "" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := &http.Client{}
	jar, _ := cookiejar.New(&cookiejar.Options{})
	client.Jar = jar

	// Empty UserField/PassField should default to "username"/"password"
	cfg := LoginConfig{
		LoginURL: server.URL + "/login",
		Username: "test",
		Password: "test",
	}

	err := Authenticate(client, cfg)
	if err != nil {
		t.Fatalf("Expected success with default field names, got: %v", err)
	}
}
