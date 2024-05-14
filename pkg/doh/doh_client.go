package doh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/zmap/dns"
)

const dohMediaType string = "application/dns-message"

type DOHClient struct {
	httpClient *http.Client
	endpoint   url.URL
}

// DOH client must be initialized before using it
func (d *DOHClient) Initialize(timeout time.Duration) {
	d.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 10 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   false,
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 200,
			MaxConnsPerHost:     200,
		},
		Timeout: timeout,
	}
}

// Supply set_endpoint with resolver hostname, path is set for POST requests
// GET requests require "?dns=<domain>" at the end of the path
func (d *DOHClient) setEndpoint(resolver string) {
	d.endpoint = url.URL{
		Scheme: "https",
		Host:   resolver,
		Path:   "/dns-query",
	}
}

func (d *DOHClient) createRequest(message *dns.Msg) (request *http.Request, err error) {
	message_wire_format, err := message.Pack()
	if err != nil {
		return nil, err
	}
	request, err = http.NewRequest(http.MethodPost, d.endpoint.String(), bytes.NewReader(message_wire_format))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", dohMediaType)
	request.Header.Set("Accept", dohMediaType)

	return request, err
}

func (d *DOHClient) ExchangeDOH(message *dns.Msg, address string) (r *dns.Msg, rtt time.Duration, err error) {
	d.setEndpoint(address)

	request, err := d.createRequest(message)
	if err != nil {
		return nil, 0, err
	}

	timeStamp := time.Now()

	response, err := d.httpClient.Do(request)
	if err != nil {
		return nil, 0, err
	}

	defer response.Body.Close()

	switch {
	case response.StatusCode != http.StatusOK:
		return nil, 0, fmt.Errorf("DOH server returned HTTP %q, expected: %d", response.Status, http.StatusOK)
	case response.Header.Get("Content-Type") != dohMediaType:
		return nil, 0, fmt.Errorf("unexpected Content-Type returned by DOH server %q, expected %q", response.Header.Get("Content-Type"), dohMediaType)
	}

	response_wire_format, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, 0, err
	}

	roundTripTime := time.Since(timeStamp)

	responseMessage := new(dns.Msg)
	if err := responseMessage.Unpack(response_wire_format); err != nil {
		return responseMessage, 0, err
	}

	return responseMessage, roundTripTime, nil
}
