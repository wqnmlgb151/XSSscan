package model

// ParamType defines where a parameter appears in the request
type ParamType string

const (
	ParamQuery  ParamType = "query"
	ParamBody   ParamType = "body"
	ParamHeader ParamType = "header"
	ParamPath   ParamType = "path"
	ParamCookie ParamType = "cookie"
)

// Parameter represents an injectable input point
type Parameter struct {
	Name  string    `json:"name" yaml:"name"`
	Value string    `json:"value" yaml:"value"`
	Type  ParamType `json:"type" yaml:"type"`
}
