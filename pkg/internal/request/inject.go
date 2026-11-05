package request

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

// InjectTarget makes an independent target before changing one parameter.
func InjectTarget(target model.Target, parameter model.Parameter, value string) (model.Target, error) {
	target.Headers = CloneHeaders(target.Headers)
	target.Cookies = CloneCookies(target.Cookies)
	switch parameter.Type {
	case model.ParamQuery:
		u, err := url.Parse(target.URL)
		if err != nil {
			return target, err
		}
		values := u.Query()
		values.Set(parameter.Name, value)
		u.RawQuery = values.Encode()
		target.URL = u.String()
	case model.ParamBody:
		target.Body = InjectBodyValue(target.Body, parameter.Name, value, target.Headers)
	case model.ParamHeader:
		if target.Headers == nil {
			target.Headers = make(map[string]string)
		}
		target.Headers[parameter.Name] = value
	case model.ParamCookie:
		for _, cookie := range target.Cookies {
			if cookie != nil && cookie.Name == parameter.Name {
				cookie.Value = value
				return target, nil
			}
		}
		target.Cookies = append(target.Cookies, &http.Cookie{Name: parameter.Name, Value: value})
	case model.ParamPath:
		var err error
		target.URL, err = InjectPathValue(target.URL, parameter.Name, parameter.Value, value)
		if err != nil {
			return target, err
		}
	default:
		return target, fmt.Errorf("unsupported parameter type: %s", parameter.Type)
	}
	return target, nil
}
