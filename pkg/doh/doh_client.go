package doh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"sync"

	"github.com/zmap/dns"
)

const dohMediaType string = "application/dns-message"

var lock = &sync.Mutex{}
var httpClientInstance *http.Client

type DOHClient struct {
	httpClient     *http.Client
	endpoint       url.URL
	Timeout        time.Duration
	RetriedRequest bool
}

func CreateHTTPClient(timeout time.Duration) *http.Client {
	if httpClientInstance == nil {
		lock.Lock()
		defer lock.Unlock()
		if httpClientInstance == nil {
			httpClientInstance = &http.Client{
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Timeout:   timeout,
						KeepAlive: 0,
					}).DialContext,
					TLSHandshakeTimeout: timeout,
					DisableKeepAlives:   false,
					MaxIdleConns:        0,
					MaxIdleConnsPerHost: 100,
					MaxConnsPerHost:     100,
					ForceAttemptHTTP2:   true,
				},
				Timeout: timeout,
			}
		}
	}
	return httpClientInstance
}

func (d *DOHClient) SetHTTPClient(httpClient *http.Client) {
	d.httpClient = httpClient
}

func (d *DOHClient) SetTimeout(timeout time.Duration) {
	d.Timeout = timeout
	d.RetriedRequest = false
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

	defer closeHTTPBody(response.Body)

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

func closeHTTPBody(r io.ReadCloser) error {
	io.Copy(io.Discard, r)
	return r.Close()
}
