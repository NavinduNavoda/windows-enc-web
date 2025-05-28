package main

import (
	"fmt"
	"net/http"
	"text/template"

	"github.com/NavinduNavoda/helpers/cryp"
	"github.com/NavinduNavoda/helpers/wincred"
)

type PageData struct {
	Encout      string
	Decout      string
	CredSuccMsg string
	CredErrMsg  string
	Credout     string
	EncSuccMsg  string
	EncErrMsg   string
	DecSuccMsg  string
	DecErrMsg   string
}

func main() {

	tmpl := template.Must(template.ParseGlob("templates/*.html"))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := PageData{
			Encout:      "",
			Decout:      "",
			CredSuccMsg: "",
			CredErrMsg:  "",
			Credout:     "",
			EncSuccMsg:  "",
			EncErrMsg:   "",
			DecSuccMsg:  "",
			DecErrMsg:   "",
		}
		tmpl.ExecuteTemplate(w, "index", data)
	})

	http.HandleFunc("/encrypt", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()
		text := r.FormValue("text")
		targetName := r.FormValue("credential")
		_, key, err := wincred.ReadCredential(targetName)

		if err != nil {
			data := PageData{
				Encout:      "",
				Decout:      "",
				CredSuccMsg: "",
				CredErrMsg:  "",
				EncSuccMsg:  "",
				EncErrMsg:   err.Error(),
				DecSuccMsg:  "",
				DecErrMsg:   "",
			}
			tmpl.ExecuteTemplate(w, "index", data)
			return
		}

		encriptedText, err := cryp.Encrypt(text, key) // 256-bit base64 encoded key// Example base64 encoded key

		var data PageData
		if err != nil {
			data = PageData{
				Encout:      "",
				Decout:      "",
				CredSuccMsg: "",
				CredErrMsg:  "",
				EncSuccMsg:  "",
				EncErrMsg:   err.Error(),
				DecSuccMsg:  "",
				DecErrMsg:   "",
			}
			tmpl.ExecuteTemplate(w, "index", data)
			return
		}

		data = PageData{
			Encout:      encriptedText,
			Decout:      "",
			CredSuccMsg: "",
			CredErrMsg:  "",
			EncSuccMsg:  "Encryption successful!",
			EncErrMsg:   "",
			DecSuccMsg:  "",
			DecErrMsg:   "",
		}
		tmpl.ExecuteTemplate(w, "index", data)
	})

	http.HandleFunc("/decrypt", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		text := r.FormValue("text")
		targetName := r.FormValue("credential")
		_, key, err := wincred.ReadCredential(targetName)

		if err != nil {
			data := PageData{
				Encout:      "",
				Decout:      "",
				CredSuccMsg: "",
				CredErrMsg:  "",
				EncSuccMsg:  "",
				EncErrMsg:   "",
				DecSuccMsg:  "",
				DecErrMsg:   err.Error(),
			}
			tmpl.ExecuteTemplate(w, "index", data)
			return
		}

		decryptedText, err := cryp.Decrypt(text, key) // 256-bit base64 encoded key// Example base64 encoded key

		var data PageData
		if err != nil {
			data = PageData{
				Encout:      "",
				Decout:      "",
				CredSuccMsg: "",
				CredErrMsg:  "",
				EncSuccMsg:  "",
				EncErrMsg:   "",
				DecSuccMsg:  "",
				DecErrMsg:   err.Error(),
			}
			tmpl.ExecuteTemplate(w, "index", data)
			return
		}

		data = PageData{
			Encout:      "",
			Decout:      decryptedText,
			CredSuccMsg: "",
			CredErrMsg:  "",
			EncSuccMsg:  "",
			EncErrMsg:   "",
			DecSuccMsg:  "Decryption successful!",
			DecErrMsg:   "",
		}
		tmpl.ExecuteTemplate(w, "index", data)
	})

	http.HandleFunc("/create-cred", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		key := r.FormValue("key")
		targetName := r.FormValue("credential")

		var data PageData
		err := wincred.WriteCredential(targetName, "", key)
		if err != nil {
			data = PageData{
				Encout:      "",
				Decout:      "",
				CredSuccMsg: "",
				CredErrMsg:  "Error saving credential: " + err.Error(),
				EncSuccMsg:  "",
				EncErrMsg:   "",
				DecSuccMsg:  "",
				DecErrMsg:   "",
			}
			tmpl.ExecuteTemplate(w, "index", data)
			return
		}

		data = PageData{
			Encout:      "",
			Decout:      "",
			CredSuccMsg: "saved successfully!",
			CredErrMsg:  "",
			EncSuccMsg:  "",
			EncErrMsg:   "",
			DecSuccMsg:  "",
			DecErrMsg:   "",
		}
		tmpl.ExecuteTemplate(w, "index", data)
	})

	http.HandleFunc("/find-cred", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		targetName := r.FormValue("credential")
		var data PageData
		_, key, err := wincred.ReadCredential(targetName)
		if err != nil {
			data = PageData{
				Encout:      "",
				Decout:      "",
				CredSuccMsg: "",
				CredErrMsg:  err.Error(),
				EncSuccMsg:  "",
				EncErrMsg:   "",
				DecSuccMsg:  "",
				DecErrMsg:   "",
			}
			tmpl.ExecuteTemplate(w, "index", data)
			return
		}
		data = PageData{
			Encout:      "",
			Decout:      "",
			CredSuccMsg: "Credential found!",
			Credout:     "Credential for " + targetName + ": " + key,
			CredErrMsg:  "",
			EncSuccMsg:  "",
			EncErrMsg:   "",
			DecSuccMsg:  "",
			DecErrMsg:   "",
		}
		tmpl.ExecuteTemplate(w, "index", data)
	})

	http.HandleFunc("/del-cred", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		targetName := r.FormValue("credential")
		var data PageData
		err := wincred.DeleteCredential(targetName)
		if err != nil {
			data = PageData{
				Encout:      "",
				Decout:      "",
				CredSuccMsg: "",
				CredErrMsg:  err.Error(),
				EncSuccMsg:  "",
				EncErrMsg:   "",
				DecSuccMsg:  "",
				DecErrMsg:   "",
			}
			tmpl.ExecuteTemplate(w, "index", data)
			return
		}
		data = PageData{
			Encout:      "",
			Decout:      "",
			CredSuccMsg: "Credential Deleted!",
			Credout:     "",
			CredErrMsg:  "",
			EncSuccMsg:  "",
			EncErrMsg:   "",
			DecSuccMsg:  "",
			DecErrMsg:   "",
		}
		tmpl.ExecuteTemplate(w, "index", data)
	})

	fmt.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
