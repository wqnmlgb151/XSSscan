package model

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

func (s Severity) Score() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}
