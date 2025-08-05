package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/justinas/alice"
	"github.com/tech-manthan/secure-auth/db/models"
	myjwt "github.com/tech-manthan/secure-auth/server/middleware/myJwt"
	"github.com/tech-manthan/secure-auth/server/templates"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panicf("Recovered! Panic : %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "/logout", "/deleteUser":
		default:
		}
	}

	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCSRFFromReq(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{
			CSRFSecret:    csrfSecret,
			SecretMessage: "Hello Manthan",
		})
	case "/login":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage{BAlertUser: false, AlertMsg: ""})
		case "POST":
		default:
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage{BAlertUser: false, AlertMsg: ""})
		case "POST":
		default:
		}
	case "/logout":
	case "/deleteUser":
	default:
	}
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)
	http.SetCookie(*w, &refreshCookie)

	refreshToken, refreshErr := r.Cookie("RefreshToken")

	if refreshErr == http.ErrNoCookie {
		return
	} else if refreshErr != nil {
		log.Panicf("Panic : %+v", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
	}

	myjwt.RevokeRefreshToken(refreshToken.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		Expires:  time.Now().Add(models.AuthTokenValidTime),
		HttpOnly: true,
	}
	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		Expires:  time.Now().Add(models.RefreshTokenValidTime),
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)
	http.SetCookie(*w, &refreshCookie)
}

func grabCSRFFromReq(r *http.Request) string {
	csrf := r.FormValue("X-CSRF-Token")

	if csrf != "" {
		return csrf
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}
