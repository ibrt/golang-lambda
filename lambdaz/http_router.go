package lambdaz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gorilla/schema"
	"github.com/ibrt/golang-bites/jsonz"
	"github.com/ibrt/golang-errors/errorz"
	"github.com/ibrt/golang-inject-logs/logz"
	"github.com/ibrt/golang-inject/injectz"
	"github.com/ibrt/golang-validation/vz"
)

type contextKey int

const (
	httpRequestContextKey contextKey = iota
	httpResponseContextKey
)

var (
	_ HTTPRequestAuthorizer     = &staticAPIKeyHTTPRequestAuthorizer{}
	_ HTTPRequestUnmarshaler    = &restHTTPRequestUnmarshaler{}
	_ HTTPResponseMarshalerFunc = RestHTTPResponseMarshaler
	_ HTTPErrorMarshalerFunc    = RestHTTPErrorMarshaler
)

// HTTPRequestContext describes the context for a HTTP request.
type HTTPRequestContext struct {
	event *events.APIGatewayV2HTTPRequest
}

// GetHTTPRequestContext extracts the *HTTPRequestContext from context, panics on error.
func GetHTTPRequestContext(ctx context.Context) *HTTPRequestContext {
	return ctx.Value(httpRequestContextKey).(*HTTPRequestContext)
}

// GetEvent returns the original APIGatewayV2HTTPRequest event.
func (c *HTTPRequestContext) GetEvent() *events.APIGatewayV2HTTPRequest {
	return c.event
}

// HTTPResponseContext describes the context for a HTTP response.
type HTTPResponseContext struct {
	status  int
	headers http.Header
	cookies []http.Cookie
}

// GetHTTPResponseContext extracts the *HTTPResponseContext from context, panics on error.
func GetHTTPResponseContext(ctx context.Context) *HTTPResponseContext {
	return ctx.Value(httpResponseContextKey).(*HTTPResponseContext)
}

// SetStatus sets the response status.
func (c *HTTPResponseContext) SetStatus(status int) {
	c.status = status
}

// GetHeaders returns the editable response headers.
func (c *HTTPResponseContext) GetHeaders() http.Header {
	return c.headers
}

// AddCookie adds a cookie to the response.
func (c *HTTPResponseContext) AddCookie(cookie http.Cookie) {
	c.cookies = append(c.cookies, cookie)
}

// HTTPMethod describes a HTTP method.
type HTTPMethod string

// Valid implements the vz.SimpleValidator interface.
func (m HTTPMethod) Valid() bool {
	switch m {
	case Delete, Get, Head, Options, Patch, Post, Put:
		return true
	default:
		return false
	}
}

// String implements the fmt.Stringer interface.
func (m HTTPMethod) String() string {
	return string(m)
}

// Known HTTP methods.
const (
	Delete  HTTPMethod = "DELETE"
	Get     HTTPMethod = "GET"
	Head    HTTPMethod = "HEAD"
	Options HTTPMethod = "OPTIONS"
	Patch   HTTPMethod = "PATCH"
	Post    HTTPMethod = "POST"
	Put     HTTPMethod = "PUT"
)

// HTTPRouteKey describes a parsed HTTP route key.
type HTTPRouteKey struct {
	Raw    string
	Method HTTPMethod
	Path   string
}

// ParseHTTPRouteKey parses a HTTP route key. Note that the parsing logic is not particularly strict.
func ParseHTTPRouteKey(rawRouteKey string) (*HTTPRouteKey, error) {
	if rawRouteKey == "$default" {
		return nil, errorz.Errorf("$default route key is not (yet) supported", errorz.Skip())
	}

	parts := strings.SplitN(rawRouteKey, " ", 2)
	if len(parts) != 2 {
		return nil, errorz.Errorf("invalid route key: %v", errorz.A(rawRouteKey), errorz.Skip())
	}

	method := HTTPMethod(parts[0])
	if !method.Valid() {
		return nil, errorz.Errorf("invalid route key: invalid method: %v", errorz.A(method), errorz.Skip())
	}

	path := parts[1]
	if strings.Contains(path, "{proxy+}") {
		return nil, errorz.Errorf("{proxy+} path parameter is not (yet) supported", errorz.Skip())
	}

	return &HTTPRouteKey{
		Raw:    rawRouteKey,
		Method: method,
		Path:   path,
	}, nil
}

// HTTPRequestAuthorizer describes an unmarshaler for a HTTP request.
type HTTPRequestAuthorizer interface {
	Authorize(ctx context.Context) error
}

// HTTPRequestAuthorizerFunc implements the HTTPRequestAuthorizer interface.
type HTTPRequestAuthorizerFunc func(ctx context.Context) error

// Authorize a HTTP request.
func (f HTTPRequestAuthorizerFunc) Authorize(ctx context.Context) error {
	return f(ctx)
}

type staticAPIKeyHTTPRequestAuthorizer struct {
	apiKey string
}

// NewStaticAPIKeyHTTPRequestAuthorizer initializes a new HTTPRequestAuthorizer
func NewStaticAPIKeyHTTPRequestAuthorizer(apiKey string) HTTPRequestAuthorizer {
	return &staticAPIKeyHTTPRequestAuthorizer{
		apiKey: apiKey,
	}
}

// Authorize implements the HTTPRequestAuthorizer interface.
func (a *staticAPIKeyHTTPRequestAuthorizer) Authorize(ctx context.Context) error {
	if apiKey := GetHTTPRequestContext(ctx).event.Headers["x-api-key"]; apiKey == "" {
		return NewErrUnauthorized("missing API key", errorz.Skip())
	} else if apiKey != a.apiKey {
		return NewErrUnauthorized("invalid API key", errorz.Skip())
	} else {
		return nil
	}
}

// HTTPRequestUnmarshaler describes an unmarshaler for a HTTP request.
type HTTPRequestUnmarshaler interface {
	Unmarshal(ctx context.Context) (interface{}, error)
}

// HTTPRequestUnmarshalerFunc implements the HTTPRequestUnmarshaler interface.
type HTTPRequestUnmarshalerFunc func(ctx context.Context) (interface{}, error)

// Unmarshal a HTTP request.
func (f HTTPRequestUnmarshalerFunc) Unmarshal(ctx context.Context) (interface{}, error) {
	return f(ctx)
}

type restHTTPRequestUnmarshaler struct {
	unmarshalBody                  bool
	unmarshalQueryStringParameters bool
	unmarshalPathParameters        bool
	requireExtractUser             bool

	reqType       reflect.Type
	schemaDecoder *schema.Decoder
}

// RestHTTPRequestUnmarshalerOption describe an option for restHTTPRequestUnmarshaler.
type RestHTTPRequestUnmarshalerOption func(u *restHTTPRequestUnmarshaler)

// NoUnmarshalBody describes a RestHTTPRequestUnmarshalerOption.
func NoUnmarshalBody(u *restHTTPRequestUnmarshaler) {
	u.unmarshalBody = false
}

// NoUnmarshalQueryStringParameters describes a RestHTTPRequestUnmarshalerOption.
func NoUnmarshalQueryStringParameters(u *restHTTPRequestUnmarshaler) {
	u.unmarshalQueryStringParameters = false
}

// NoUnmarshalPathParameters describes a RestHTTPRequestUnmarshalerOption.
func NoUnmarshalPathParameters(u *restHTTPRequestUnmarshaler) {
	u.unmarshalPathParameters = false
}

// RequireExtractUser describes a RestHTTPRequestUnmarshalerOption.
func RequireExtractUser(u *restHTTPRequestUnmarshaler) {
	u.requireExtractUser = true
}

// NewRestHTTPRequestUnmarshaler initializes a new HTTPRequestUnmarshaler.
func NewRestHTTPRequestUnmarshaler(reqTemplate interface{}, options ...RestHTTPRequestUnmarshalerOption) HTTPRequestUnmarshaler {
	reqType := reflect.TypeOf(reqTemplate)
	reqValue := reflect.New(reqType).Interface()

	errorz.Assertf(reqType.Kind() == reflect.Struct, "reqTemplate must be a struct")
	errorz.Assertf(vz.IsValidatable(reqValue), "reqTemplate must implement vz.Validator or vz.SimpleValidator")

	u := &restHTTPRequestUnmarshaler{
		unmarshalBody:                  true,
		unmarshalQueryStringParameters: true,
		unmarshalPathParameters:        true,
		requireExtractUser:             false,
		reqType:                        reqType,
		schemaDecoder:                  schema.NewDecoder(),
	}

	u.schemaDecoder.SetAliasTag("json")
	u.schemaDecoder.IgnoreUnknownKeys(false)

	for _, option := range options {
		option(u)
	}

	_, ok := reqValue.(logz.UserExtractor)
	errorz.Assertf(!u.requireExtractUser || ok, "reqTemplate must implement logz.UserExtractor")

	return u
}

// Unmarshal implements the HTTPRequestUnmarshaler interface.
func (u *restHTTPRequestUnmarshaler) Unmarshal(ctx context.Context) (interface{}, error) {
	event := GetHTTPRequestContext(ctx).event
	req := reflect.New(u.reqType).Interface()

	if !u.unmarshalBody && event.Body != "" {
		return nil, NewErrBadRequest("unexpected body", errorz.Skip())
	}

	if u.unmarshalBody {
		if event.Body == "" {
			return nil, NewErrBadRequest("missing body", errorz.Skip())
		}

		bodyReader := io.Reader(strings.NewReader(event.Body))
		if event.IsBase64Encoded {
			bodyReader = base64.NewDecoder(base64.StdEncoding, bodyReader)
		}

		d := json.NewDecoder(bodyReader)
		d.DisallowUnknownFields()

		if err := d.Decode(req); err != nil {
			return nil, WrapErrBadRequest(err, errorz.Skip())
		}
	}

	if u.unmarshalQueryStringParameters && event.RawQueryString != "" {
		values, err := url.ParseQuery(event.RawQueryString)
		if err != nil {
			return nil, WrapErrBadRequest(err, errorz.Skip())
		}

		if err := u.schemaDecoder.Decode(req, values); err != nil {
			return nil, WrapErrBadRequest(err, errorz.Skip())
		}
	}

	if u.unmarshalPathParameters && len(event.PathParameters) == 0 {
		values := url.Values{}

		for k, v := range event.PathParameters {
			values[k] = []string{v}
		}

		if err := u.schemaDecoder.Decode(req, values); err != nil {
			return nil, WrapErrBadRequest(err, errorz.Skip())
		}
	}

	if err := vz.Validate(req); err != nil {
		return nil, WrapErrBadRequest(err, errorz.Skip())
	}

	if userExtractor, ok := req.(logz.UserExtractor); ok {
		logz.Get(ctx).SetUser(userExtractor.ExtractUser())

	}

	return req, nil
}

// HTTPResponseMarshaler describes a marshaler for a HTTP response.
type HTTPResponseMarshaler interface {
	Marshal(ctx context.Context, resp interface{}) *events.APIGatewayV2HTTPResponse
}

// HTTPResponseMarshalerFunc implements the HTTPResponseMarshaler interface.
type HTTPResponseMarshalerFunc func(ctx context.Context, resp interface{}) *events.APIGatewayV2HTTPResponse

// Marshal a HTTP response.
func (f HTTPResponseMarshalerFunc) Marshal(ctx context.Context, resp interface{}) *events.APIGatewayV2HTTPResponse {
	return f(ctx, resp)
}

// RestHTTPResponseMarshaler is a HTTPResponseMarshaler.
func RestHTTPResponseMarshaler(ctx context.Context, resp interface{}) *events.APIGatewayV2HTTPResponse {
	respCtx := GetHTTPResponseContext(ctx)

	var body string
	if resp != nil {
		respCtx.headers.Set("Content-Type", "application/json; charset=utf-8")
		body = jsonz.MustMarshalIndentDefaultString(resp)
	}

	var cookies []string
	for _, cookie := range respCtx.cookies {
		cookies = append(cookies, cookie.String())
	}

	return &events.APIGatewayV2HTTPResponse{
		StatusCode:        respCtx.status,
		MultiValueHeaders: respCtx.headers,
		Body:              body,
		Cookies:           cookies,
	}
}

// HTTPErrorMarshaler describes a marshaler for a HTTP error.
type HTTPErrorMarshaler interface {
	Marshal(ctx context.Context, err error) *events.APIGatewayV2HTTPResponse
}

// HTTPErrorMarshalerFunc implements the HTTPErrorMarshaler interface.
type HTTPErrorMarshalerFunc func(ctx context.Context, err error) *events.APIGatewayV2HTTPResponse

// Marshal a HTTP error.
func (f HTTPErrorMarshalerFunc) Marshal(ctx context.Context, err error) *events.APIGatewayV2HTTPResponse {
	return f(ctx, err)
}

// RestHTTPErrorMarshaler is a HTTPErrorMarshaler.
func RestHTTPErrorMarshaler(ctx context.Context, err error) *events.APIGatewayV2HTTPResponse {
	respCtx := GetHTTPResponseContext(ctx)
	errResp := errorz.ToSummary(err)

	if errResp.Status == 0 {
		errResp.Status = http.StatusInternalServerError
	}

	respCtx.SetStatus(errResp.Status.Int())
	return RestHTTPResponseMarshaler(ctx, errResp)
}

// HTTPEndpoint describes an endpoint.
type HTTPEndpoint struct {
	requestAuthorizer  HTTPRequestAuthorizer
	requestUnmarshaler HTTPRequestUnmarshaler
	responseMarshaler  HTTPResponseMarshaler
	errorMarshaler     HTTPErrorMarshaler
	handlerFunc        interface{}
	routeKey           *HTTPRouteKey
}

// NewHTTPEndpoint initializes a new HTTPEndpoint.
func NewHTTPEndpoint(
	rawRouteKey string,
	requestAuthorizer HTTPRequestAuthorizer,
	requestUnmarshaler HTTPRequestUnmarshaler,
	responseMarshaler HTTPResponseMarshaler,
	errorMarshaler HTTPErrorMarshaler,
	handlerFunc interface{}) *HTTPEndpoint {

	errorz.Assertf(errorMarshaler != nil, "errorMarshaler unexpectedly nil", errorz.Skip())
	errorz.Assertf(handlerFunc != nil, "handlerFunc unexpectedly nil", errorz.Skip())

	routeKey, err := ParseHTTPRouteKey(rawRouteKey)
	errorz.MaybeMustWrap(err, errorz.Skip())

	handlerFuncType := reflect.TypeOf(handlerFunc)
	errorz.Assertf(handlerFuncType.Kind() == reflect.Func, "handlerFunc must be a function")

	if requestUnmarshaler == nil {
		errorz.Assertf(handlerFuncType.NumIn() == 1, "handlerFunc without requestUnmarshaler must accept a single argument")
		errorz.Assertf(handlerFuncType.In(0) == reflect.TypeOf((*context.Context)(nil)).Elem(), "handlerFunc argument must be context.Context")
	} else {
		errorz.Assertf(handlerFuncType.NumIn() == 2, "handlerFunc with requestUnmarshaler must accept two arguments")
		errorz.Assertf(handlerFuncType.In(0) == reflect.TypeOf((*context.Context)(nil)).Elem(), "handlerFunc first argument must be context.Context")
		errorz.Assertf(handlerFuncType.In(1).Kind() == reflect.Ptr, "handlerFunc second argument must be a struct pointer")
		errorz.Assertf(handlerFuncType.In(1).Elem().Kind() == reflect.Struct, "handlerFunc second argument must be a struct pointer")
	}

	if responseMarshaler == nil {
		errorz.Assertf(handlerFuncType.NumOut() == 1, "handlerFunc without responseMarshaler must return a single value")
		errorz.Assertf(handlerFuncType.Out(0) == reflect.TypeOf((*error)(nil)).Elem(), "handlerFunc return value must be error")
	} else {
		errorz.Assertf(handlerFuncType.NumOut() == 2, "handlerFunc with responseMarshaler must return two values")
		errorz.Assertf(handlerFuncType.Out(0).Kind() == reflect.Ptr, "handlerFunc first return value must be struct pointer")
		errorz.Assertf(handlerFuncType.Out(0).Elem().Kind() == reflect.Struct, "handlerFunc first return value must be struct pointer")
		errorz.Assertf(handlerFuncType.Out(1) == reflect.TypeOf((*error)(nil)).Elem(), "handlerFunc second return value must be error")
	}

	e := &HTTPEndpoint{
		requestAuthorizer:  requestAuthorizer,
		requestUnmarshaler: requestUnmarshaler,
		responseMarshaler:  responseMarshaler,
		errorMarshaler:     errorMarshaler,
		handlerFunc:        handlerFunc,
		routeKey:           routeKey,
	}

	return e
}

// GetRouteKey returns the route key.
func (e *HTTPEndpoint) GetRouteKey() *HTTPRouteKey {
	return e.routeKey
}

// Router implements a request router.
type Router struct {
	injector  injectz.Injector
	endpoints map[string]*HTTPEndpoint
}

// NewRouter initializes a new router.
func NewRouter() *Router {
	return &Router{
		endpoints: make(map[string]*HTTPEndpoint),
	}
}

// Register registers an endpoint.
func (r *Router) Register(endpoint *HTTPEndpoint) *Router {
	errorz.Assertf(r.endpoints[endpoint.routeKey.Raw] == nil, "route key already registered: %v", errorz.A(endpoint.routeKey))
	r.endpoints[endpoint.routeKey.Raw] = endpoint
	return r
}

// SetInjector sets the (optional) context injector.
func (r *Router) SetInjector(injector injectz.Injector) *Router {
	r.injector = injector
	return r
}

// GetEndpoints gets a slice of registered endpoints.
func (r *Router) GetEndpoints() []*HTTPEndpoint {
	endpoints := make([]*HTTPEndpoint, 0, len(r.endpoints))
	for _, endpoint := range r.endpoints {
		endpoints = append(endpoints, endpoint)
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].routeKey.Raw < endpoints[j].routeKey.Raw
	})

	return endpoints
}

// Handler provides a handler function that can be registered with the Lambda SDK.
func (r *Router) Handler(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	if r.injector != nil {
		ctx = r.injector(ctx)
	}

	ctx = context.WithValue(ctx, httpRequestContextKey, &HTTPRequestContext{
		event: &event,
	})

	ctx = context.WithValue(ctx, httpResponseContextKey, &HTTPResponseContext{
		status:  http.StatusOK,
		headers: http.Header{},
		cookies: nil,
	})

	ctx, releaseTransaction := logz.Get(ctx).TraceHTTPRequestServer(r.eventToSyntheticHTTPRequest(&event))
	defer releaseTransaction()
	r.addEventMetadata(ctx, &event)

	endpoint, ok := r.endpoints[event.RouteKey]
	if !ok {
		// Note: this is not really a "not found". More like a misconfiguration between the router and he API.
		err := errorz.Errorf("unknown route key: %v", errorz.A(event.RouteKey))
		logz.Get(ctx).Error(err)
		return events.APIGatewayV2HTTPResponse{}, err
	}

	resp, err := func() (resp interface{}, err error) {
		defer func() {
			if rErr := errorz.MaybeWrapRecover(recover()); rErr != nil {
				resp = nil
				err = rErr
			}
			if err != nil {
				logz.Get(ctx).Error(err)
			}
		}()

		if endpoint.requestAuthorizer != nil {
			if err := endpoint.requestAuthorizer.Authorize(ctx); err != nil {
				return nil, errorz.Wrap(err)
			}
		}

		req, err := endpoint.requestUnmarshaler.Unmarshal(ctx)
		if err != nil {
			return nil, errorz.Wrap(err)
		}

		return r.invoke(ctx, endpoint.handlerFunc, req)
	}()

	if err != nil {
		logz.Get(ctx).Error(err)
		return *endpoint.errorMarshaler.Marshal(ctx, err), nil
	}

	return *endpoint.responseMarshaler.Marshal(ctx, resp), nil
}

// ShallowClone returns a shallow clone of the router.
func (r *Router) ShallowClone() *Router {
	endpoints := make(map[string]*HTTPEndpoint, len(r.endpoints))
	for k, v := range r.endpoints {
		endpoints[k] = v
	}
	return &Router{
		injector:  r.injector,
		endpoints: endpoints,
	}
}

func (r *Router) eventToSyntheticHTTPRequest(event *events.APIGatewayV2HTTPRequest) (*http.Request, []byte) {
	// TODO(ibrt): Add a little bit of complexity to avoid double parsing the request and figure out if there's a less
	// iffy way to achieve this, given that Sentry events hold a parsed request but scopes want a *http.Request.

	routeKey, err := ParseHTTPRouteKey(event.RouteKey)
	if err != nil {
		routeKey = &HTTPRouteKey{
			Method: HTTPMethod(event.RequestContext.HTTP.Method),
			Path:   event.RequestContext.HTTP.Path,
		}
	}

	var body []byte

	if event.Body != "" {
		if event.IsBase64Encoded {
			if decBody, err := base64.StdEncoding.DecodeString(event.Body); err == nil {
				body = decBody
			} else {
				body = []byte(event.Body)
			}
		} else {
			body = []byte(event.Body)
		}
	}

	httpReq, err := http.NewRequest(
		routeKey.Method.String(),
		fmt.Sprintf("https://%v%v", event.RequestContext.DomainName, routeKey.Path),
		nil)
	errorz.MaybeMustWrap(err)
	httpReq.RemoteAddr = event.RequestContext.HTTP.SourceIP

	if len(event.Cookies) > 0 {
		httpReq.Header.Set("Cookie", event.Cookies[0])
	}

	for k, v := range event.Headers {
		httpReq.Header.Set(k, v)
	}

	return httpReq, body
}

func (r *Router) addEventMetadata(ctx context.Context, event *events.APIGatewayV2HTTPRequest) {
	logs := logz.Get(ctx)

	logs.AddMetadata("Request Context", event.RequestContext)
	logs.AddMetadata("Query String Parameters", event.QueryStringParameters)
	logs.AddMetadata("Path Parameters", event.PathParameters)
	logs.AddMetadata("Stage Variables", event.StageVariables)
}

func (r *Router) invoke(ctx context.Context, handlerFunc, req interface{}) (interface{}, error) {
	ret := reflect.ValueOf(handlerFunc).Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(req),
	})

	vErr := ret[len(ret)-1]
	if err, ok := vErr.Interface().(error); ok && err != nil {
		return nil, errorz.Wrap(err, errorz.Skip())
	}

	if len(ret) > 1 {
		return ret[0].Interface(), nil
	}

	return nil, nil
}
