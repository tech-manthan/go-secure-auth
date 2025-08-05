package templates

import (
	"html/template"
	"log"
	"net/http"
)

type LoginPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RegisterPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RestrictedPage struct {
	CSRFSecret    string
	SecretMessage string
}

var templates = template.Must(template.ParseFiles("./server/templates/templateFiles/login.tmpl",
	"./server/templates/templateFiles/register.tmpl",
	"./server/templates/templateFiles/restricted.tmpl",
))

func RenderTemplate(w http.ResponseWriter, tmpl string, p interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".tmpl", p)

	if err != nil {
		log.Printf("Template error : %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}
