package testlambdaz_test

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/ibrt/golang-bites/jsonz"
	"github.com/ibrt/golang-errors/errorz"
	"github.com/ibrt/golang-fixtures/fixturez"
	"github.com/ibrt/golang-inject-http/httpz/testhttpz"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/ibrt/golang-lambda/lambdaz/testlambdaz"
)

type Suite struct {
	*fixturez.DefaultConfigMixin
	HTTP *testhttpz.MockHelper
}

func TestHTTPSimulator(t *testing.T) {
	fixturez.RunSuite(t, &Suite{})
}

func (s *Suite) TestHTTPSimulator(ctx context.Context, t *testing.T) {
	simulator := testlambdaz.NewHTTPSimulator(
		&testlambdaz.HTTPSimulatorConfig{
			Routes: map[string]*testlambdaz.HTTPSimulatorConfigRoute{
				"POST /p1/{pk}": {
					IntegrationName: "function",
				},
			},
			AWSProxyIntegrations: map[string]*testlambdaz.HTTPSimulatorConfigAWSProxyIntegration{
				"function": {
					URL: "http://function:12345",
				},
			},
		},
		func(_ context.Context) context.Context {
			return ctx
		})

	srv := httptest.NewServer(simulator.GetEchoForTest())
	defer srv.Close()

	gock.New("http://function:12345").
		Post("").
		Reply(http.StatusOK).
		JSON(&events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusOK,
			MultiValueHeaders: map[string][]string{
				"X-Custom-Header": {"value"},
			},
			Body: `{ "value": "value" }`,
		})

	httpResp, err := (&http.Client{
		Transport: &http.Transport{},
	}).Post(
		srv.URL+"/p1/pv",
		"application/json; charset=utf-8",
		strings.NewReader(jsonz.MustMarshalString(map[string]string{
			"value": "value",
		})))
	fixturez.RequireNoError(t, err)
	defer errorz.IgnoreClose(httpResp.Body)
	require.Equal(t, http.StatusOK, httpResp.StatusCode)
	require.Equal(t, "value", httpResp.Header.Get("X-Custom-Header"))

	buf, err := ioutil.ReadAll(httpResp.Body)
	fixturez.RequireNoError(t, err)
	require.Equal(t, "{ \"value\": \"value\" }", string(buf))
}
