package runner

import (
	"github.com/refraction-networking/conjure/application/lib"
)

type Runner interface {
	Run()
}

type DefaultRunner struct {
	Config *lib.Config
}

func NewRunner() Runner {

	return &DefaultRunner{
		Config: nil,
	}
}

func (dr *DefaultRunner) Run() {

}
