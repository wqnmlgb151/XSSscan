package model

import ctx "github.com/xsscan/xsscan/pkg/context"

type InjectionPoint struct {
	Target     Target         `json:"target"`
	Parameter  Parameter      `json:"parameter"`
	Contexts   []ctx.Context  `json:"contexts"`
	Reflection ReflectionInfo `json:"reflection"`
}

type ReflectionInfo struct {
	Offset  int    `json:"offset"`
	Length  int    `json:"length"`
	Snippet string `json:"snippet"`
}
