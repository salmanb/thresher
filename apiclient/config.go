package apiclient

import (
	"errors"
	"github.com/salmanb/thresher/auth"
	tsapi "github.com/threatstack/ts/api"
)

func NewClientConfig(opts *auth.Opts) (*tsapi.Config, error) {

	if opts.User == "" {
		err := errors.New("No value specified for User field")
		return nil, err
	}
	if opts.Key == "" {
		err := errors.New("No value specified for Key field")
		return nil, err
	}
	if opts.Org == "" {
		err := errors.New("No value specified for Org field")
		return nil, err
	}

	tsconfig := &tsapi.Config{
		User: opts.User,
		Key:  opts.Key,
		Org:  opts.Org,
	}

	return tsconfig, nil
}
