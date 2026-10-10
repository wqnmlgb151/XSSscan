package httpclient

import "github.com/xsscan/xsscan/pkg/model"

// ExchangeError preserves the HTTP diagnostic without altering report evidence.
type ExchangeError struct {
	Message string
	Cause   error
	HTTP    model.HTTPExchange
}

func (e *ExchangeError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}
func (e *ExchangeError) Unwrap() error { return e.Cause }
