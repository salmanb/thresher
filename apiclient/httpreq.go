package apiclient

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	tsapi "github.com/threatstack/ts/api"
)

type RatelimitError struct {
	ErrMsg     string
	StatusCode int
}

func (e *RatelimitError) Error() string {
	return fmt.Sprintf("%s : HTTP/%d", e.ErrMsg, e.StatusCode)
}

type NotFoundError struct {
	ErrMsg     string
	StatusCode int
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("%s : HTTP/%d", e.ErrMsg, e.StatusCode)
}

func NewHttpReq(config tsapi.Config, apiendpoint string) (*http.Request, error) {
	if config.User == "" {
		err := errors.New("No value specified for User field")
		return nil, err
	}
	if config.Key == "" {
		err := errors.New("No value specified for Key field")
		return nil, err
	}
	if config.Org == "" {
		err := errors.New("No value specified for Org field")
		return nil, err
	}

	req, err := tsapi.Request(config, "GET", apiendpoint, nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func GetData(req *http.Request) ([]byte, error) {
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return body, nil
	} else if resp.StatusCode == 429 {
		return nil, &RatelimitError{"Rate limited by server", 429}
	} else if resp.StatusCode == 404 {
		return nil, &NotFoundError{"Object not found", 404}
	} else {
		err := fmt.Errorf("HTTP error -- server returned HTTP/%d", resp.StatusCode)
		return nil, err
	}
}
