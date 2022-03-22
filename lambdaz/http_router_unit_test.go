package lambdaz

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/golang/mock/gomock"
	"github.com/ibrt/golang-bites/jsonz"
	"github.com/ibrt/golang-errors/errorz"
	"github.com/ibrt/golang-fixtures/fixturez"
	"github.com/ibrt/golang-inject-logs/logz"
	"github.com/ibrt/golang-inject-logs/logz/testlogz"
	"github.com/ibrt/golang-validation/vz"
	"github.com/stretchr/testify/require"
)

type Suite struct {
	*fixturez.DefaultConfigMixin
	Logs *testlogz.MockHelper
}

func TestHTTPRouterUnit(t *testing.T) {
	fixturez.RunSuite(t, &Suite{})
}

var (
	_ vz.Validator       = &testRequest{}
	_ vz.Validator       = &testRequestUserExtractor{}
	_ logz.UserExtractor = &testRequestUserExtractor{}
)

type testRequest struct {
	Value string `json:"value" validate:"required"`
}

// Validate implements the vz.Validator interface.
func (r *testRequest) Validate() error {
	return vz.ValidateStruct(r)
}

type testRequestUserExtractor struct {
	Value string `json:"value" validate:"required"`
}

// Validate implements the vz.Validator interface.
func (r *testRequestUserExtractor) Validate() error {
	return vz.ValidateStruct(r)
}

// ExtractUser implements the logz.UserExtractor interface.
func (r *testRequestUserExtractor) ExtractUser() *logz.User {
	return &logz.User{
		ID: "user-id",
	}
}

type testResponse struct {
	Value string `json:"value"`
}

func (s *Suite) TestGetHTTPRequestContext(ctx context.Context, t *testing.T) {
	event := &events.APIGatewayV2HTTPRequest{
		RouteKey: "GET /endpoint",
	}
	reqCtx := newHTTPRequestContext(event)
	require.Equal(t, event, reqCtx.GetEvent())
	require.Equal(t, reqCtx, GetHTTPRequestContext(context.WithValue(ctx, httpRequestContextKey, reqCtx)))
}

func (s *Suite) TestGetHTTPResponseContext(ctx context.Context, t *testing.T) {
	respCtx := newHTTPResponseContext()
	require.Equal(t, http.StatusOK, respCtx.status)
	require.Equal(t, http.Header{}, respCtx.headers)
	require.Nil(t, respCtx.cookies)

	respCtx.SetStatus(http.StatusBadRequest)
	respCtx.GetHeaders().Set("k", "v")
	respCtx.AddCookie(http.Cookie{Name: "cookie"})

	require.Equal(t, http.StatusBadRequest, respCtx.status)
	require.Equal(t, http.Header{"K": []string{"v"}}, respCtx.headers)
	require.Equal(t, []http.Cookie{{Name: "cookie"}}, respCtx.cookies)

	require.Equal(t, respCtx, GetHTTPResponseContext(context.WithValue(ctx, httpResponseContextKey, respCtx)))
}

func (s *Suite) TestHTTPMethod(_ context.Context, t *testing.T) {
	require.Equal(t, "POST", Post.String())
	require.False(t, HTTPMethod("unknown").Valid())
	require.True(t, Any.Valid())
	require.True(t, Delete.Valid())
	require.True(t, Get.Valid())
	require.True(t, Head.Valid())
	require.True(t, Options.Valid())
	require.True(t, Patch.Valid())
	require.True(t, Post.Valid())
	require.True(t, Put.Valid())
}

func (s *Suite) TestParseRouteKey(_ context.Context, t *testing.T) {
	routeKey, err := ParseHTTPRouteKey("$default")
	fixturez.RequireNoError(t, err)
	require.Equal(t, &HTTPRouteKey{
		Raw:       "$default",
		IsDefault: true,
	}, routeKey)

	routeKey, err = ParseHTTPRouteKey("POST /path")
	fixturez.RequireNoError(t, err)
	require.Equal(t, &HTTPRouteKey{
		Raw:    "POST /path",
		Method: Post,
		Path:   "/path",
	}, routeKey)

	routeKey, err = ParseHTTPRouteKey("bad")
	require.EqualError(t, err, "invalid route key: bad")
	require.Nil(t, routeKey)

	routeKey, err = ParseHTTPRouteKey("BAD /path")
	require.EqualError(t, err, "invalid route key: invalid method: BAD")
	require.Nil(t, routeKey)
}

func (s *Suite) TestStaticAPIKeyHTTPRequestAuthorizer(ctx context.Context, t *testing.T) {
	fixturez.RequireNoError(t, HTTPRequestAuthorizerFunc(func(ctx context.Context) error { return nil }).Authorize(ctx))
	authorizer := NewStaticAPIKeyHTTPRequestAuthorizer("api-key")

	fixturez.RequireNoError(t, authorizer.Authorize(
		context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Headers: map[string]string{
				staticAPIKeyHeader: "api-key",
			},
		}))))

	require.EqualError(t, authorizer.Authorize(
		context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Headers: map[string]string{
				staticAPIKeyHeader: "",
			},
		}))), "unauthorized: missing API key")

	require.EqualError(t, authorizer.Authorize(
		context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Headers: map[string]string{
				staticAPIKeyHeader: "bad",
			},
		}))), "unauthorized: invalid API key")
}

func (s *Suite) TestJSONHTTPRequestUnmarshaler(ctx context.Context, t *testing.T) {
	resp, err := HTTPRequestUnmarshalerFunc(func(ctx context.Context) (interface{}, error) { return "resp", nil }).Unmarshal(ctx)
	fixturez.RequireNoError(t, err)
	require.Equal(t, "resp", resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			// intentionally empty
		})))
	require.EqualError(t, err, "bad request: missing body")
	require.Nil(t, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body: "bad",
		})))
	require.EqualError(t, err, "bad request: invalid character 'b' looking for beginning of value")
	require.Nil(t, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body: `{ "unknown": "unknown" }`,
		})))
	require.EqualError(t, err, `bad request: json: unknown field "unknown"`)
	require.Nil(t, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body: `{ "value": "value" }`,
		})))
	fixturez.RequireNoError(t, err)
	require.Equal(t, &testRequest{Value: "value"}, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body: `{ "value": "" }`,
		})))
	require.EqualError(t, err, "bad request: failed validation: Key: 'testRequest.value' Error:Field validation for 'value' failed on the 'required' tag")
	require.Nil(t, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body:            base64.StdEncoding.EncodeToString([]byte(`{ "value": "value" }`)),
			IsBase64Encoded: true,
		})))
	fixturez.RequireNoError(t, err)
	require.Equal(t, &testRequest{Value: "value"}, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body:           `{}`,
			RawQueryString: "value=value",
		})))
	fixturez.RequireNoError(t, err)
	require.Equal(t, &testRequest{Value: "value"}, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body:           `{}`,
			RawQueryString: ";",
		})))
	require.EqualError(t, err, `bad request: invalid semicolon separator in query`)
	require.Nil(t, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body:           `{}`,
			RawQueryString: "unknown=unknown",
		})))
	require.EqualError(t, err, `bad request: schema: invalid path "unknown"`)
	require.Nil(t, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body: `{}`,
			PathParameters: map[string]string{
				"value": "value",
			},
		})))
	fixturez.RequireNoError(t, err)
	require.Equal(t, &testRequest{Value: "value"}, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body: `{}`,
			PathParameters: map[string]string{
				"unknown": "unknown",
			},
		})))
	require.EqualError(t, err, `bad request: schema: invalid path "unknown"`)
	require.Nil(t, resp)

	s.Logs.Mock.EXPECT().SetUser(gomock.Any(), gomock.Eq(&logz.User{
		ID: "user-id",
	}))

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequestUserExtractor{}).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body: `{ "value": "value" }`,
		})))
	fixturez.RequireNoError(t, err)
	require.Equal(t, &testRequestUserExtractor{Value: "value"}, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}, NoUnmarshalBody).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body: `{}`,
		})))
	require.EqualError(t, err, `bad request: unexpected body`)
	require.Nil(t, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}, NoUnmarshalQueryStringParameters).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body:           `{ "value": "value" }`,
			RawQueryString: "value=other",
		})))
	fixturez.RequireNoError(t, err)
	require.Equal(t, &testRequest{Value: "value"}, resp)

	resp, err = NewJSONHTTPRequestUnmarshaler(testRequest{}, NoUnmarshalPathParameters).
		Unmarshal(context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(&events.APIGatewayV2HTTPRequest{
			Body: `{ "value": "value" }`,
			PathParameters: map[string]string{
				"value": "other",
			},
		})))
	fixturez.RequireNoError(t, err)
	require.Equal(t, &testRequest{Value: "value"}, resp)

	fixturez.RequirePanicsWith(t, "reqTemplate must be a struct", func() {
		NewJSONHTTPRequestUnmarshaler(&testRequest{})
	})

	fixturez.RequirePanicsWith(t, "reqTemplate must implement vz.Validator or vz.SimpleValidator", func() {
		NewJSONHTTPRequestUnmarshaler(struct{}{})
	})

	fixturez.RequirePanicsWith(t, "reqTemplate must implement logz.UserExtractor", func() {
		NewJSONHTTPRequestUnmarshaler(testRequest{}, RequireExtractUser)
	})
}

func (s *Suite) TestJSONHTTPResponseMarshaler(ctx context.Context, t *testing.T) {
	require.Equal(t,
		&events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusOK,
			MultiValueHeaders: map[string][]string{
				"Content-Type": {"application/json; charset=utf-8"},
			},
			Body: "{\n  \"value\": \"value\"\n}",
		},
		HTTPResponseMarshalerFunc(JSONHTTPResponseMarshaler).Marshal(
			context.WithValue(ctx, httpResponseContextKey, newHTTPResponseContext()),
			&testResponse{Value: "value"}))

	require.Equal(t,
		&events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusAccepted,
			MultiValueHeaders: map[string][]string{
				"Content-Type": {"application/json; charset=utf-8"},
			},
			Body: "{\n  \"value\": \"value\"\n}",
		},
		JSONHTTPResponseMarshaler(
			context.WithValue(ctx, httpResponseContextKey, &HTTPResponseContext{
				status:  http.StatusAccepted,
				headers: http.Header{},
			}),
			&testResponse{Value: "value"}))

	require.Equal(t,
		&events.APIGatewayV2HTTPResponse{
			StatusCode:        http.StatusOK,
			MultiValueHeaders: map[string][]string{},
		},
		JSONHTTPResponseMarshaler(
			context.WithValue(ctx, httpResponseContextKey, newHTTPResponseContext()),
			nil))

	require.Equal(t,
		&events.APIGatewayV2HTTPResponse{
			StatusCode:        http.StatusAccepted,
			MultiValueHeaders: map[string][]string{},
			Cookies:           []string{"test="},
		},
		JSONHTTPResponseMarshaler(
			context.WithValue(ctx, httpResponseContextKey, &HTTPResponseContext{
				status:  http.StatusAccepted,
				headers: http.Header{},
				cookies: []http.Cookie{{Name: "test"}},
			}),
			nil))
}

func (s *Suite) TestJSONHTTPErrorMarshaler(ctx context.Context, t *testing.T) {
	err := errorz.Errorf("test error")
	errSummary := errorz.ToSummary(err)
	errSummary.Status = http.StatusInternalServerError
	jsonErrSummary := jsonz.MustMarshalIndentDefaultString(errSummary)
	require.Equal(t,
		&events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			MultiValueHeaders: map[string][]string{
				"Content-Type": {"application/json; charset=utf-8"},
			},
			Body: jsonErrSummary,
		},
		HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler).Marshal(
			context.WithValue(ctx, httpResponseContextKey, newHTTPResponseContext()),
			err))

	err = errorz.Errorf("test error", errorz.Status(http.StatusBadRequest))
	errSummary = errorz.ToSummary(err)
	jsonErrSummary = jsonz.MustMarshalIndentDefaultString(errSummary)
	require.Equal(t,
		&events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusBadRequest,
			MultiValueHeaders: map[string][]string{
				"Content-Type": {"application/json; charset=utf-8"},
			},
			Body: jsonErrSummary,
		},
		HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler).Marshal(
			context.WithValue(ctx, httpResponseContextKey, newHTTPResponseContext()),
			err))
}

func (s *Suite) TestNewHTTPEndpoint(_ context.Context, t *testing.T) {
	fixturez.RequirePanicsWith(t, "errorMarshaler unexpectedly nil", func() {
		NewHTTPEndpoint("", nil, nil, nil, nil, nil)
	})

	fixturez.RequirePanicsWith(t, "handlerFunc unexpectedly nil", func() {
		NewHTTPEndpoint("", nil, nil, nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), nil)
	})

	fixturez.RequirePanicsWith(t, "invalid route key: bad", func() {
		NewHTTPEndpoint("bad", nil, nil, nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), "")
	})

	fixturez.RequirePanicsWith(t, "handlerFunc must be a function", func() {
		NewHTTPEndpoint("POST /path", nil, nil, nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), "")
	})

	fixturez.RequirePanicsWith(t, "handlerFunc without requestUnmarshaler must accept a single argument", func() {
		NewHTTPEndpoint("POST /path", nil, nil, nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func() {})
	})

	fixturez.RequirePanicsWith(t, "handlerFunc argument must be context.Context", func() {
		NewHTTPEndpoint("POST /path", nil, nil, nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(string) {})
	})

	fixturez.RequirePanicsWith(t, "handlerFunc with requestUnmarshaler must accept two arguments", func() {
		NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func() {})
	})

	fixturez.RequirePanicsWith(t, "handlerFunc first argument must be context.Context", func() {
		NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(string, string) {})
	})

	fixturez.RequirePanicsWith(t, "handlerFunc second argument must be a struct pointer", func() {
		NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context, string) {})
	})

	fixturez.RequirePanicsWith(t, "handlerFunc without responseMarshaler must return a single value", func() {
		NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context, *testResponse) {})
	})

	fixturez.RequirePanicsWith(t, "handlerFunc return value must be error", func() {
		NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context, *testResponse) string { return "" })
	})

	fixturez.RequirePanicsWith(t, "handlerFunc with responseMarshaler must return two values", func() {
		NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), HTTPResponseMarshalerFunc(JSONHTTPResponseMarshaler), HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context, *testResponse) {})
	})

	fixturez.RequirePanicsWith(t, "handlerFunc first return value must be struct pointer", func() {
		NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), HTTPResponseMarshalerFunc(JSONHTTPResponseMarshaler), HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context, *testResponse) (string, string) { return "", "" })
	})

	fixturez.RequirePanicsWith(t, "handlerFunc second return value must be error", func() {
		NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), HTTPResponseMarshalerFunc(JSONHTTPResponseMarshaler), HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context, *testResponse) (*testResponse, string) { return nil, "" })
	})

	fixturez.RequireNotPanics(t, func() {
		e := NewHTTPEndpoint("POST /path", nil, nil, nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context) error { return nil })
		require.Equal(t, &HTTPRouteKey{Raw: "POST /path", Method: Post, Path: "/path"}, e.GetRouteKey())
	})

	fixturez.RequireNotPanics(t, func() {
		e := NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context, *testResponse) error { return nil })
		require.Equal(t, &HTTPRouteKey{Raw: "POST /path", Method: Post, Path: "/path"}, e.GetRouteKey())
	})

	fixturez.RequireNotPanics(t, func() {
		e := NewHTTPEndpoint("POST /path", nil, nil, HTTPResponseMarshalerFunc(JSONHTTPResponseMarshaler), HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context) (*testResponse, error) { return nil, nil })
		require.Equal(t, &HTTPRouteKey{Raw: "POST /path", Method: Post, Path: "/path"}, e.GetRouteKey())
	})

	fixturez.RequireNotPanics(t, func() {
		e := NewHTTPEndpoint("POST /path", nil, NewJSONHTTPRequestUnmarshaler(testRequest{}), HTTPResponseMarshalerFunc(JSONHTTPResponseMarshaler), HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context, *testResponse) (*testResponse, error) { return nil, nil })
		require.Equal(t, &HTTPRouteKey{Raw: "POST /path", Method: Post, Path: "/path"}, e.GetRouteKey())
	})
}

func (s *Suite) TestNewHTTPRouter(_ context.Context, t *testing.T) {
	injector := func(ctx context.Context) context.Context {
		return ctx
	}

	r1 := NewHTTPRouter()
	require.Nil(t, r1.injector)

	r1.SetInjector(injector)
	require.NotNil(t, r1.injector)

	e1 := NewHTTPEndpoint("POST /p1", nil, nil, nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context) error { return nil })
	e2 := NewHTTPEndpoint("POST /p2", nil, nil, nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context) error { return nil })
	e3 := NewHTTPEndpoint("POST /p3", nil, nil, nil, HTTPErrorMarshalerFunc(JSONHTTPErrorMarshaler), func(context.Context) error { return nil })

	r1.Register(e1)
	r1.Register(e2)

	fixturez.RequirePanicsWith(t, "route key already registered: POST /p1", func() {
		r1.Register(e1)
	})

	require.Equal(t, []*HTTPEndpoint{e1, e2}, r1.GetEndpoints())

	r2 := r1.ShallowClone()
	r2.Register(e3)
	require.Equal(t, []*HTTPEndpoint{e1, e2}, r1.GetEndpoints())
	require.Equal(t, []*HTTPEndpoint{e1, e2, e3}, r2.GetEndpoints())
}

func (s *Suite) TestHTTPRouter_PrepareContext(ctx context.Context, t *testing.T) {
	event := &events.APIGatewayV2HTTPRequest{
		RouteKey:       "POST /p1/{pk1}",
		RawPath:        "/p1/pv1",
		RawQueryString: "qs1=qv1",
		Cookies: []string{
			"name=",
		},
		Headers: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		QueryStringParameters: map[string]string{
			"qs1": "qv1",
		},
		PathParameters: map[string]string{
			"pk1": "pv1",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1/{pk1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:    "POST",
				Path:      "/p1/pv1",
				Protocol:  "HTTP",
				SourceIP:  "1.2.3.4",
				UserAgent: "go",
			},
		},
		StageVariables: map[string]string{
			"sk1": "sv1",
		},
		Body:            `{ "bk1": "bv1" }`,
		IsBase64Encoded: false,
	}

	var cReq *http.Request
	var cReqBody []byte

	s.Logs.Mock.EXPECT().TraceHTTPRequestServer(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *http.Request, reqBody []byte) (context.Context, func()) {
		cReq = req
		cReqBody = reqBody
		return ctx, func() {}
	})

	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Request Context"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Query String Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Path Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Stage Variables"), gomock.Any())

	ctx, _ = NewHTTPRouter().prepareContext(ctx, event)
	require.Equal(t, newHTTPRequestContext(event), GetHTTPRequestContext(ctx))
	require.Equal(t, newHTTPResponseContext(), GetHTTPResponseContext(ctx))

	require.Equal(t, "POST", cReq.Method)
	require.Equal(t, "https:///p1/%7Bpk1%7D", cReq.URL.String())
	require.Equal(t, []byte(`{ "bk1": "bv1" }`), cReqBody)
}

func (s *Suite) TestHTTPRouter_PrepareContext_RouteKeyAny(ctx context.Context, t *testing.T) {
	event := &events.APIGatewayV2HTTPRequest{
		RouteKey:       "ANY /p1/{pk1}",
		RawPath:        "/p1/pv1",
		RawQueryString: "qs1=qv1",
		Cookies: []string{
			"name=",
		},
		Headers: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		QueryStringParameters: map[string]string{
			"qs1": "qv1",
		},
		PathParameters: map[string]string{
			"pk1": "pv1",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1/{pk1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:    "POST",
				Path:      "/p1/pv1",
				Protocol:  "HTTP",
				SourceIP:  "1.2.3.4",
				UserAgent: "go",
			},
		},
		StageVariables: map[string]string{
			"sk1": "sv1",
		},
		Body:            `{ "bk1": "bv1" }`,
		IsBase64Encoded: false,
	}

	var cReq *http.Request
	var cReqBody []byte

	s.Logs.Mock.EXPECT().TraceHTTPRequestServer(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *http.Request, reqBody []byte) (context.Context, func()) {
		cReq = req
		cReqBody = reqBody
		return ctx, func() {}
	})

	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Request Context"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Query String Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Path Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Stage Variables"), gomock.Any())

	ctx, _ = NewHTTPRouter().prepareContext(ctx, event)
	require.Equal(t, newHTTPRequestContext(event), GetHTTPRequestContext(ctx))
	require.Equal(t, newHTTPResponseContext(), GetHTTPResponseContext(ctx))

	require.Equal(t, "POST", cReq.Method)
	require.Equal(t, "https:///p1/%7Bpk1%7D", cReq.URL.String())
	require.Equal(t, []byte(`{ "bk1": "bv1" }`), cReqBody)
}

func (s *Suite) TestHTTPRouter_PrepareContext_RouteKeyFallback(ctx context.Context, t *testing.T) {
	event := &events.APIGatewayV2HTTPRequest{
		RouteKey:       "bad",
		RawPath:        "/p1/pv1",
		RawQueryString: "qs1=qv1",
		Cookies: []string{
			"name=",
		},
		Headers: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		QueryStringParameters: map[string]string{
			"qs1": "qv1",
		},
		PathParameters: map[string]string{
			"pk1": "pv1",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1/{pk1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:    "POST",
				Path:      "/p1/pv1",
				Protocol:  "HTTP",
				SourceIP:  "1.2.3.4",
				UserAgent: "go",
			},
		},
		StageVariables: map[string]string{
			"sk1": "sv1",
		},
		Body:            `{ "bk1": "bv1" }`,
		IsBase64Encoded: false,
	}

	var cReq *http.Request
	var cReqBody []byte

	s.Logs.Mock.EXPECT().TraceHTTPRequestServer(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *http.Request, reqBody []byte) (context.Context, func()) {
		cReq = req
		cReqBody = reqBody
		return ctx, func() {}
	})

	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Request Context"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Query String Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Path Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Stage Variables"), gomock.Any())

	ctx, _ = NewHTTPRouter().prepareContext(ctx, event)
	require.Equal(t, newHTTPRequestContext(event), GetHTTPRequestContext(ctx))
	require.Equal(t, newHTTPResponseContext(), GetHTTPResponseContext(ctx))

	require.Equal(t, "POST", cReq.Method)
	require.Equal(t, "https:///p1/pv1", cReq.URL.String())
	require.Equal(t, []byte(`{ "bk1": "bv1" }`), cReqBody)
}

func (s *Suite) TestHTTPRouter_PrepareContext_RouteKeyDefault(ctx context.Context, t *testing.T) {
	event := &events.APIGatewayV2HTTPRequest{
		RouteKey:       "$default",
		RawPath:        "/p1/pv1",
		RawQueryString: "qs1=qv1",
		Cookies: []string{
			"name=",
		},
		Headers: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		QueryStringParameters: map[string]string{
			"qs1": "qv1",
		},
		PathParameters: map[string]string{
			"pk1": "pv1",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1/{pk1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:    "POST",
				Path:      "/p1/pv1",
				Protocol:  "HTTP",
				SourceIP:  "1.2.3.4",
				UserAgent: "go",
			},
		},
		StageVariables: map[string]string{
			"sk1": "sv1",
		},
		Body:            `{ "bk1": "bv1" }`,
		IsBase64Encoded: false,
	}

	var cReq *http.Request
	var cReqBody []byte

	s.Logs.Mock.EXPECT().TraceHTTPRequestServer(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *http.Request, reqBody []byte) (context.Context, func()) {
		cReq = req
		cReqBody = reqBody
		return ctx, func() {}
	})

	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Request Context"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Query String Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Path Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Stage Variables"), gomock.Any())

	ctx, _ = NewHTTPRouter().prepareContext(ctx, event)
	require.Equal(t, newHTTPRequestContext(event), GetHTTPRequestContext(ctx))
	require.Equal(t, newHTTPResponseContext(), GetHTTPResponseContext(ctx))

	require.Equal(t, "POST", cReq.Method)
	require.Equal(t, "https:///p1/pv1", cReq.URL.String())
	require.Equal(t, []byte(`{ "bk1": "bv1" }`), cReqBody)
}

func (s *Suite) TestHTTPRouter_PrepareContext_Base64EncodedBody(ctx context.Context, t *testing.T) {
	event := &events.APIGatewayV2HTTPRequest{
		RouteKey:       "bad",
		RawPath:        "/p1/pv1",
		RawQueryString: "qs1=qv1",
		Cookies: []string{
			"name=",
		},
		Headers: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		QueryStringParameters: map[string]string{
			"qs1": "qv1",
		},
		PathParameters: map[string]string{
			"pk1": "pv1",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1/{pk1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:    "POST",
				Path:      "/p1/pv1",
				Protocol:  "HTTP",
				SourceIP:  "1.2.3.4",
				UserAgent: "go",
			},
		},
		StageVariables: map[string]string{
			"sk1": "sv1",
		},
		Body:            base64.StdEncoding.EncodeToString([]byte(`{ "bk1": "bv1" }`)),
		IsBase64Encoded: true,
	}

	var cReq *http.Request
	var cReqBody []byte

	s.Logs.Mock.EXPECT().TraceHTTPRequestServer(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *http.Request, reqBody []byte) (context.Context, func()) {
		cReq = req
		cReqBody = reqBody
		return ctx, func() {}
	})

	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Request Context"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Query String Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Path Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Stage Variables"), gomock.Any())

	type ck int
	injector := func(ctx context.Context) context.Context {
		return context.WithValue(ctx, ck(1), "cv1")
	}

	ctx, _ = NewHTTPRouter().SetInjector(injector).prepareContext(ctx, event)
	require.Equal(t, newHTTPRequestContext(event), GetHTTPRequestContext(ctx))
	require.Equal(t, newHTTPResponseContext(), GetHTTPResponseContext(ctx))
	require.Equal(t, "cv1", ctx.Value(ck(1)))

	require.Equal(t, "POST", cReq.Method)
	require.Equal(t, "https:///p1/pv1", cReq.URL.String())
	require.Equal(t, []byte(`{ "bk1": "bv1" }`), cReqBody)
}

func (s *Suite) TestHTTPRouter_PrepareContext_InvalidBase64EncodedBody(ctx context.Context, t *testing.T) {
	event := &events.APIGatewayV2HTTPRequest{
		RouteKey:       "bad",
		RawPath:        "/p1/pv1",
		RawQueryString: "qs1=qv1",
		Cookies: []string{
			"name=",
		},
		Headers: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		QueryStringParameters: map[string]string{
			"qs1": "qv1",
		},
		PathParameters: map[string]string{
			"pk1": "pv1",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey: "POST /p1/{pk1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:    "POST",
				Path:      "/p1/pv1",
				Protocol:  "HTTP",
				SourceIP:  "1.2.3.4",
				UserAgent: "go",
			},
		},
		StageVariables: map[string]string{
			"sk1": "sv1",
		},
		Body:            "bad",
		IsBase64Encoded: true,
	}

	var cReq *http.Request
	var cReqBody []byte

	s.Logs.Mock.EXPECT().TraceHTTPRequestServer(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req *http.Request, reqBody []byte) (context.Context, func()) {
		cReq = req
		cReqBody = reqBody
		return ctx, func() {}
	})

	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Request Context"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Query String Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Path Parameters"), gomock.Any())
	s.Logs.Mock.EXPECT().AddMetadata(gomock.Any(), gomock.Eq("Stage Variables"), gomock.Any())

	ctx, _ = NewHTTPRouter().prepareContext(ctx, event)
	require.Equal(t, newHTTPRequestContext(event), GetHTTPRequestContext(ctx))
	require.Equal(t, newHTTPResponseContext(), GetHTTPResponseContext(ctx))

	require.Equal(t, "https:///p1/pv1", cReq.URL.String())
	require.Equal(t, []byte(`bad`), cReqBody)
}
