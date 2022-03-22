package lambdaz_test

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/ibrt/golang-errors/errorz"
	"github.com/ibrt/golang-fixtures/fixturez"
	"github.com/ibrt/golang-inject-logs/logz/testlogz"
	"github.com/ibrt/golang-validation/vz"
	"github.com/stretchr/testify/require"

	"github.com/ibrt/golang-lambda/lambdaz"
)

type Suite struct {
	*fixturez.DefaultConfigMixin
	Logs *testlogz.Helper
}

func TestHTTPRouter(t *testing.T) {
	fixturez.RunSuite(t, &Suite{})
}

type testRequest struct {
	Value string `json:"value" validate:"required"`
}

type testResponse struct {
	Value string `json:"value"`
}

var (
	_ lambdaz.HTTPResponseMarshaler = &panicResponseMarshaler{}
)

type panicResponseMarshaler struct {
	// intentionally empty
}

// GetResponseType implements the HTTPResponseMarshaler interface.
func (*panicResponseMarshaler) GetResponseType() *reflect.Type {
	return nil
}

// Marshal implements the HTTPResponseMarshaler interface.
func (*panicResponseMarshaler) Marshal(_ context.Context, _ interface{}) *events.APIGatewayV2HTTPResponse {
	panic(errorz.Errorf("test error"))
}

// Validate implements the vz.Validator interface.
func (r *testRequest) Validate() error {
	return vz.ValidateStruct(r)
}

func (s *Suite) TestHTTPRouter(ctx context.Context, t *testing.T) {
	e1 := lambdaz.NewHTTPEndpoint(
		"POST /p1",
		lambdaz.NewStaticAPIKeyHTTPRequestAuthorizer("api-key"),
		lambdaz.NewJSONHTTPRequestUnmarshaler(testRequest{}),
		lambdaz.NewJSONHTTPResponseMarshaler(testResponse{}),
		lambdaz.NewJSONHTTPErrorMarshaler(),
		func(ctx context.Context, req *testRequest) (*testResponse, error) {
			return &testResponse{
				Value: req.Value,
			}, nil
		})

	e2 := lambdaz.NewHTTPEndpoint(
		"GET /p1",
		nil,
		lambdaz.NewNoBodyHTTPRequestUnmarshaler(true),
		lambdaz.NewNoBodyHTTPResponseMarshaler(),
		lambdaz.NewJSONHTTPErrorMarshaler(),
		func(ctx context.Context) error {
			return nil
		})

	e3 := lambdaz.NewHTTPEndpoint(
		"GET /p2",
		nil,
		lambdaz.NewNoBodyHTTPRequestUnmarshaler(true),
		lambdaz.NewNoBodyHTTPResponseMarshaler(),
		lambdaz.NewJSONHTTPErrorMarshaler(),
		func(ctx context.Context) error {
			return errorz.Errorf("test error")
		})

	e4 := lambdaz.NewHTTPEndpoint(
		"GET /p3",
		nil,
		lambdaz.NewNoBodyHTTPRequestUnmarshaler(true),
		lambdaz.NewNoBodyHTTPResponseMarshaler(),
		lambdaz.NewJSONHTTPErrorMarshaler(),
		func(ctx context.Context) error {
			panic(errorz.Errorf("test error"))
		})

	e5 := lambdaz.NewHTTPEndpoint(
		"GET /p4",
		nil,
		lambdaz.NewNoBodyHTTPRequestUnmarshaler(true),
		&panicResponseMarshaler{},
		lambdaz.NewJSONHTTPErrorMarshaler(),
		func(ctx context.Context) error {
			return nil
		})

	r := lambdaz.NewHTTPRouter().
		Register(e1).
		Register(e2).
		Register(e3).
		Register(e4).
		Register(e5)

	hEvent, hErr := r.Handler(ctx, events.APIGatewayV2HTTPRequest{
		RouteKey: "POST /p1",
		RawPath:  "/p1",
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:   "POST",
				Path:     "/p1",
				Protocol: "HTTP",
				SourceIP: "1.2.3.4",
			},
		},
		Body: `{ "value": "value" }`,
	})
	fixturez.RequireNoError(t, hErr)
	require.Equal(t, http.StatusUnauthorized, hEvent.StatusCode)
	require.Equal(t, map[string][]string{
		"Content-Type": {"application/json; charset=utf-8"},
	}, hEvent.MultiValueHeaders)
	errResp := &errorz.Summary{}
	fixturez.RequireNoError(t, json.Unmarshal([]byte(hEvent.Body), errResp))
	require.Equal(t, http.StatusUnauthorized, errResp.Status.Int())
	require.Equal(t, "unauthorized: missing API key", errResp.Message)

	hEvent, hErr = r.Handler(ctx, events.APIGatewayV2HTTPRequest{
		RouteKey: "POST /p1",
		RawPath:  "/p1",
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:   "POST",
				Path:     "/p1",
				Protocol: "HTTP",
				SourceIP: "1.2.3.4",
			},
		},
		Headers: map[string]string{
			"x-api-key": "api-key",
		},
		Body: `{ "value": "value" }`,
	})
	fixturez.RequireNoError(t, hErr)
	require.Equal(t, events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusOK,
		MultiValueHeaders: map[string][]string{
			"Content-Type": {"application/json; charset=utf-8"},
		},
		Body: "{\n  \"value\": \"value\"\n}",
	}, hEvent)

	hEvent, hErr = r.Handler(ctx, events.APIGatewayV2HTTPRequest{
		RouteKey: "POST /p1",
		RawPath:  "/p1",
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:   "POST",
				Path:     "/p1",
				Protocol: "HTTP",
				SourceIP: "1.2.3.4",
			},
		},
		Headers: map[string]string{
			"x-api-key": "api-key",
		},
	})
	fixturez.RequireNoError(t, hErr)
	require.Equal(t, http.StatusBadRequest, hEvent.StatusCode)
	require.Equal(t, map[string][]string{
		"Content-Type": {"application/json; charset=utf-8"},
	}, hEvent.MultiValueHeaders)
	errResp = &errorz.Summary{}
	fixturez.RequireNoError(t, json.Unmarshal([]byte(hEvent.Body), errResp))
	require.Equal(t, http.StatusBadRequest, errResp.Status.Int())
	require.Equal(t, "bad request: missing body", errResp.Message)

	hEvent, hErr = r.Handler(ctx, events.APIGatewayV2HTTPRequest{
		RouteKey: "GET /p1",
		RawPath:  "/p1",
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:   "GET",
				Path:     "/p1",
				Protocol: "HTTP",
				SourceIP: "1.2.3.4",
			},
		},
	})
	fixturez.RequireNoError(t, hErr)
	require.Equal(t, events.APIGatewayV2HTTPResponse{
		StatusCode:        http.StatusOK,
		MultiValueHeaders: map[string][]string{},
	}, hEvent)

	hEvent, hErr = r.Handler(ctx, events.APIGatewayV2HTTPRequest{
		RouteKey: "GET /p2",
		RawPath:  "/p2",
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "GET /p2",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:   "GET",
				Path:     "/p2",
				Protocol: "HTTP",
				SourceIP: "1.2.3.4",
			},
		},
	})
	fixturez.RequireNoError(t, hErr)
	require.Equal(t, http.StatusInternalServerError, hEvent.StatusCode)
	require.Equal(t, map[string][]string{
		"Content-Type": {"application/json; charset=utf-8"},
	}, hEvent.MultiValueHeaders)
	errResp = &errorz.Summary{}
	fixturez.RequireNoError(t, json.Unmarshal([]byte(hEvent.Body), errResp))
	require.Equal(t, http.StatusInternalServerError, errResp.Status.Int())
	require.Equal(t, "test error", errResp.Message)

	hEvent, hErr = r.Handler(ctx, events.APIGatewayV2HTTPRequest{
		RouteKey: "GET /p3",
		RawPath:  "/p3",
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "GET /p3",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:   "GET",
				Path:     "/p3",
				Protocol: "HTTP",
				SourceIP: "1.2.3.4",
			},
		},
	})
	fixturez.RequireNoError(t, hErr)
	require.Equal(t, http.StatusInternalServerError, hEvent.StatusCode)
	require.Equal(t, map[string][]string{
		"Content-Type": {"application/json; charset=utf-8"},
	}, hEvent.MultiValueHeaders)
	errResp = &errorz.Summary{}
	fixturez.RequireNoError(t, json.Unmarshal([]byte(hEvent.Body), errResp))
	require.Equal(t, http.StatusInternalServerError, errResp.Status.Int())
	require.Equal(t, "test error", errResp.Message)

	hEvent, hErr = r.Handler(ctx, events.APIGatewayV2HTTPRequest{
		RouteKey: "GET /unknown",
		RawPath:  "/unknown",
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "GET /unknown",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:   "GET",
				Path:     "/unknown",
				Protocol: "HTTP",
				SourceIP: "1.2.3.4",
			},
		},
	})
	require.EqualError(t, hErr, "unknown route key: GET /unknown")
	require.Equal(t, events.APIGatewayV2HTTPResponse{}, hEvent)

	hEvent, hErr = r.Handler(ctx, events.APIGatewayV2HTTPRequest{
		RouteKey: "GET /p4",
		RawPath:  "/p4",
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "GET /p4",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:   "GET",
				Path:     "/p4",
				Protocol: "HTTP",
				SourceIP: "1.2.3.4",
			},
		},
	})
	require.EqualError(t, hErr, "test error")
	require.Equal(t, events.APIGatewayV2HTTPResponse{}, hEvent)
}
