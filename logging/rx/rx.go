package rx

import (
	"regexp"
)

var appRules = map[string]string{
	"new-registration": `\sNew\s(registration):\s`,
	"valid-connection": `took (\d+\.\d+)s`,
}

var detectorRules = map[string]string{
	"stats-logline":    `stats (\d+)`,
	"new-registration": `New registration ([^\s]+) -> ([^(,\s)]+), ([a-fA-F0-9]+)`,
	//Dec 03, 2019 16:23:43.510437 (Core 2) DEBUG: New registration 128.138.244.89:43324 -> 192.122.190.105:443, e34b2f8c34a24f36c3862458e1a909decd7d2ac5b6fa5286eed491f85ecd912d
}

type RX struct {
	regexps map[string]*regexp.Regexp
}

func GetAppRx() *RX {
	AR := RX{regexps: make(map[string]*regexp.Regexp)}

	for k, v := range appRules {
		err := AR.Add(k, v)
		if err != nil {
			return nil
		}
	}

	return &AR
}

func GetDetectorRx() *RX {
	AR := RX{regexps: make(map[string]*regexp.Regexp)}

	for k, v := range detectorRules {
		err := AR.Add(k, v)
		if err != nil {
			return nil
		}
	}

	return &AR
}

func (rx *RX) Add(key string, re string) error {
	regx, err := regexp.Compile(re)
	if err != nil {
		return err
	}

	rx.regexps[key] = regx
	return nil
}

func (rx *RX) Check(line string) (string, []string) {
	for key, regx := range rx.regexps {
		res := regx.FindStringSubmatch(line)
		if len(res) != 0 {
			return key, res
		}
	}

	return "no-match", nil
}
