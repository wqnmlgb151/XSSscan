package crawler

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

type FormOption struct {
	Value              string
	Selected, Disabled bool
}
type FormField struct {
	Name, Type, Value           string
	Checked, Disabled, Multiple bool
	HasValue                    bool
	Options                     []FormOption
}

func hasAttribute(n *html.Node, name string) bool {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return true
		}
	}
	return false
}

func nodeText(n *html.Node) string {
	var out strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			out.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return out.String()
}

func collectFormFields(form *html.Node) []FormField {
	var fields []FormField
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "select" || n.Data == "textarea") {
			kind := strings.ToLower(getAttr(n, "type"))
			if kind == "" {
				kind = "text"
			}
			if n.Data != "input" {
				kind = n.Data
			}
			field := FormField{Name: getAttr(n, "name"), Type: kind, Value: getAttr(n, "value"), Checked: hasAttribute(n, "checked"), Disabled: hasAttribute(n, "disabled"), Multiple: hasAttribute(n, "multiple"), HasValue: hasAttribute(n, "value")}
			if kind == "textarea" {
				field.Value = nodeText(n)
			}
			if kind == "select" {
				var options func(*html.Node, bool)
				options = func(item *html.Node, disabled bool) {
					disabled = disabled || hasAttribute(item, "disabled")
					if item.Type == html.ElementNode && item.Data == "option" {
						value := getAttr(item, "value")
						if !hasAttribute(item, "value") {
							value = strings.TrimSpace(nodeText(item))
						}
						field.Options = append(field.Options, FormOption{value, hasAttribute(item, "selected"), disabled})
						return
					}
					for c := item.FirstChild; c != nil; c = c.NextSibling {
						options(c, disabled)
					}
				}
				options(n, field.Disabled)
			}
			fields = append(fields, field)
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)
	return fields
}

// DefaultValues preserves non-text successful controls from the discovered form.
func (f FormInfo) DefaultValues() url.Values {
	values := url.Values{}
	if len(f.Fields) == 0 {
		for _, name := range f.Inputs {
			values.Set(name, "test")
		}
		return values
	}
	for _, field := range f.Fields {
		if field.Name == "" || field.Disabled || skipInputTypes[field.Type] || field.Type == "file" {
			continue
		}
		switch field.Type {
		case "checkbox", "radio":
			if field.Checked {
				value := field.Value
				if value == "" && !field.HasValue {
					value = "on"
				}
				values.Add(field.Name, value)
			}
		case "select":
			var selected []string
			hasSelection := false
			for _, option := range field.Options {
				if option.Selected {
					hasSelection = true
					if !field.Multiple {
						selected = nil
					}
					if !option.Disabled {
						selected = append(selected, option.Value)
					}
				}
			}
			if !field.Multiple && !hasSelection {
				for _, option := range field.Options {
					if !option.Disabled {
						selected = append(selected, option.Value)
						break
					}
				}
			}
			if !field.Multiple && len(selected) > 1 {
				selected = selected[len(selected)-1:]
			}
			for _, value := range selected {
				values.Add(field.Name, value)
			}
		case "hidden", "password":
			values.Add(field.Name, field.Value)
		case "text", "email", "search", "url", "tel", "textarea":
			values.Add(field.Name, "test")
		default:
			values.Add(field.Name, field.Value)
		}
	}
	return values
}
