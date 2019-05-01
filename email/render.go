package email

import (
	"bytes"
	htmltemplate "html/template"
	texttemplate "text/template"
	"time"
)

func renderText(templateText string, emailTemplateData interface{}) (string, error) {

	t, err := texttemplate.New("").Parse(templateText)

	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(nil)
	err = t.Execute(buf, emailTemplateData)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderHTML(templateText string, emailTemplateData interface{}) (string, error) {

	t, err := htmltemplate.New("").Funcs(funcMap).Parse(templateText)

	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(nil)
	err = t.Execute(buf, emailTemplateData)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// funcMap defines template functions that transform variables into strings in the template
var funcMap = htmltemplate.FuncMap{
	"FormatDateTime": func(t time.Time) string {
		return t.Format("15:04:05 MST on 2 January 2006")
	},
	"FormatDate": func(t time.Time) string {
		return t.Format("2 January 2006")
	},
}
