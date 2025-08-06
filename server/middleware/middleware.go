package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/tech-manthan/secure-auth/db"
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
			log.Println("In Auth Restricted section")

			AuthCookie, authErr := r.Cookie("AuthToken")

			if authErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no auth cookie")
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(401), 401)
				return
			} else if authErr != nil {
				log.Panicf("Panic : %+v", authErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			RefreshCookie, refreshErr := r.Cookie("AuthToken")

			if refreshErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no refresh cookie")
				nullifyTokenCookies(&w, r)
				// http.Error(w, http.StatusText(401), 401)
				http.Redirect(w, r, "/login", 302)
				return
			} else if refreshErr != nil {
				log.Panicf("Panic : %+v", refreshErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			csrfToken := grabCSRFFromReq(r)

			authTokenString, refreshTokenString, csrfTokenString, err := myjwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, csrfToken)

			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized attempt, JWT's not valid")
					http.Error(w, http.StatusText(401), 401)
					return
				} else {
					log.Panicf("Panic : %+v", err)
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}
			log.Println("Successfully Recreated jwts")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfTokenString)
		default:
		}
		next.ServeHTTP(w, r)
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
			r.ParseForm()

			user, uuid, err := db.LogUserIn(
				strings.Join(r.Form["username"], ""),
				strings.Join(r.Form["password"], ""),
			)

			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				// http.Error(w, http.StatusText(500), 500)
				return
			}
			log.Println("uuid :" + uuid)

			authTokenString, refreshTokenString, csrfToken, err := myjwt.CreateNewTokens(uuid, user.Role)

			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				return
			}

			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfToken)
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage{BAlertUser: false, AlertMsg: ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			_, _, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))

			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			role := "user"
			uuid, err := db.StoreUser(
				strings.Join(r.Form["username"], ""),
				strings.Join(r.Form["password"], ""),
				role,
			)

			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				return
			}
			log.Println("uuid :" + uuid)

			authTokenString, refreshTokenString, csrfToken, err := myjwt.CreateNewTokens(uuid, role)

			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				return
			}

			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfToken)
			w.WriteHeader(http.StatusCreated)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", 302)
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
