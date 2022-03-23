package lambdaz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/getsentry/sentry-go"
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

	staticAPIKeyHeader = "x-api-key"
)

var (
	_ HTTPRequestAuthorizer  = &staticAPIKeyHTTPRequestAuthorizer{}
	_ HTTPRequestUnmarshaler = &noBodyHTTPRequestUnmarshaler{}
	_ HTTPRequestUnmarshaler = &jsonHTTPRequestUnmarshaler{}
	_ HTTPResponseMarshaler  = &noBodyHTTPResponseMarshaler{}
	_ HTTPResponseMarshaler  = &jsonHTTPResponseMarshaler{}
	_ HTTPErrorMarshaler     = &jsonHTTPErrorMarshaler{}

	ctxType = reflect.TypeOf((*context.Context)(nil)).Elem()
	errType = reflect.TypeOf((*error)(nil)).Elem()
)

// HTTPRequestContext describes the context for a HTTP request.
type HTTPRequestContext struct {
	event *events.APIGatewayV2HTTPRequest
}

func newHTTPRequestContext(event *events.APIGatewayV2HTTPRequest) *HTTPRequestContext {
	return &HTTPRequestContext{
		event: event,
	}
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

func newHTTPResponseContext() *HTTPResponseContext {
	return &HTTPResponseContext{
		status:  http.StatusOK,
		headers: http.Header{},
	}
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
	case Any, Delete, Get, Head, Options, Patch, Post, Put:
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
	Any     HTTPMethod = "ANY"
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
	Raw       string
	IsDefault bool
	Method    HTTPMethod
	Path      string
}

// ParseHTTPRouteKey parses a HTTP route key.
// Note that the parsing logic is not particularly strict, rather designed to prevent accidental mistakes.
func ParseHTTPRouteKey(rawRouteKey string) (*HTTPRouteKey, error) {
	if rawRouteKey == "$default" {
		return &HTTPRouteKey{
			Raw:       rawRouteKey,
			IsDefault: true,
		}, nil
	}

	parts := strings.SplitN(rawRouteKey, " ", 2)
	if len(parts) != 2 {
		return nil, errorz.Errorf("invalid route key: %v", errorz.A(rawRouteKey), errorz.Skip())
	}

	method := HTTPMethod(parts[0])
	if !method.Valid() {
		return nil, errorz.Errorf("invalid route key: invalid method: %v", errorz.A(method), errorz.Skip())
	}

	return &HTTPRouteKey{
		Raw:    rawRouteKey,
		Method: method,
		Path:   parts[1],
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
	if apiKey := GetHTTPRequestContext(ctx).event.Headers[staticAPIKeyHeader]; apiKey == "" {
		return NewErrUnauthorized("missing API key", errorz.Skip())
	} else if apiKey != a.apiKey {
		return NewErrUnauthorized("invalid API key", errorz.Skip())
	} else {
		return nil
	}
}

// HTTPRequestUnmarshaler describes an unmarshaler for a HTTP request.
type HTTPRequestUnmarshaler interface {
	GetRequestType() *reflect.Type
	Unmarshal(ctx context.Context) (interface{}, error)
}

type noBodyHTTPRequestUnmarshaler struct {
	isStrict bool
}

// NewNoBodyHTTPRequestUnmarshaler initializes a new HTTPRequestUnmarshaler.
func NewNoBodyHTTPRequestUnmarshaler(isStrict bool) HTTPRequestUnmarshaler {
	return &noBodyHTTPRequestUnmarshaler{
		isStrict: isStrict,
	}
}

// GetRequestType implements the HTTPRequestUnmarshaler interface.
func (*noBodyHTTPRequestUnmarshaler) GetRequestType() *reflect.Type {
	return nil
}

// Unmarshal implements the HTTPRequestUnmarshaler interface.
func (u *noBodyHTTPRequestUnmarshaler) Unmarshal(ctx context.Context) (interface{}, error) {
	if u.isStrict && GetHTTPRequestContext(ctx).event.Body != "" {
		return nil, NewErrBadRequest("unexpected body", errorz.Skip())
	}

	return nil, nil
}

type jsonHTTPRequestUnmarshaler struct {
	unmarshalBody                  bool
	unmarshalQueryStringParameters bool
	unmarshalPathParameters        bool
	requireExtractUser             bool

	reqType       reflect.Type
	schemaDecoder *schema.Decoder
}

// JSONHTTPRequestUnmarshalerOption describe an option for jsonHTTPRequestUnmarshaler.
type JSONHTTPRequestUnmarshalerOption func(u *jsonHTTPRequestUnmarshaler)

// NoUnmarshalBody describes a JSONHTTPRequestUnmarshalerOption.
func NoUnmarshalBody(u *jsonHTTPRequestUnmarshaler) {
	u.unmarshalBody = false
}

// NoUnmarshalQueryStringParameters describes a JSONHTTPRequestUnmarshalerOption.
func NoUnmarshalQueryStringParameters(u *jsonHTTPRequestUnmarshaler) {
	u.unmarshalQueryStringParameters = false
}

// NoUnmarshalPathParameters describes a JSONHTTPRequestUnmarshalerOption.
func NoUnmarshalPathParameters(u *jsonHTTPRequestUnmarshaler) {
	u.unmarshalPathParameters = false
}

// RequireExtractUser describes a JSONHTTPRequestUnmarshalerOption.
func RequireExtractUser(u *jsonHTTPRequestUnmarshaler) {
	u.requireExtractUser = true
}

// NewJSONHTTPRequestUnmarshaler initializes a new HTTPRequestUnmarshaler.
func NewJSONHTTPRequestUnmarshaler(reqTemplate interface{}, options ...JSONHTTPRequestUnmarshalerOption) HTTPRequestUnmarshaler {
	reqType := reflect.TypeOf(reqTemplate)
	reqValue := reflect.New(reqType).Interface()

	errorz.Assertf(reqType.Kind() == reflect.Struct, "reqTemplate must be a struct")
	errorz.Assertf(vz.IsValidatable(reqValue), "reqTemplate must implement vz.Validator or vz.SimpleValidator")

	u := &jsonHTTPRequestUnmarshaler{
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

// GetRequestType implements the HTTPRequestUnmarshaler interface.
func (u *jsonHTTPRequestUnmarshaler) GetRequestType() *reflect.Type {
	return &u.reqType
}

// Unmarshal implements the HTTPRequestUnmarshaler interface.
func (u *jsonHTTPRequestUnmarshaler) Unmarshal(ctx context.Context) (interface{}, error) {
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

	if u.unmarshalPathParameters && len(event.PathParameters) > 0 {
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
	GetResponseType() *reflect.Type
	Marshal(ctx context.Context, resp interface{}) *events.APIGatewayV2HTTPResponse
}

type noBodyHTTPResponseMarshaler struct {
	// intentionally empty
}

// NewNoBodyHTTPResponseMarshaler initializes a new HTTPResponseMarshaler.
func NewNoBodyHTTPResponseMarshaler() HTTPResponseMarshaler {
	return &noBodyHTTPResponseMarshaler{}
}

// GetResponseType implements the HTTPResponseMarshaler interface.
func (m *noBodyHTTPResponseMarshaler) GetResponseType() *reflect.Type {
	return nil
}

// Marshal implements the HTTPResponseMarshaler interface.
func (m *noBodyHTTPResponseMarshaler) Marshal(ctx context.Context, resp interface{}) *events.APIGatewayV2HTTPResponse {
	errorz.Assertf(resp == nil, "resp unexpectedly not nil")
	respCtx := GetHTTPResponseContext(ctx)

	var cookies []string
	for _, cookie := range respCtx.cookies {
		cookies = append(cookies, cookie.String())
	}

	return &events.APIGatewayV2HTTPResponse{
		StatusCode:        respCtx.status,
		MultiValueHeaders: respCtx.headers,
		Cookies:           cookies,
	}
}

type jsonHTTPResponseMarshaler struct {
	respType reflect.Type
}

// NewJSONHTTPResponseMarshaler initializes a new HTTPResponseMarshaler.
func NewJSONHTTPResponseMarshaler(respTemplate interface{}) HTTPResponseMarshaler {
	respType := reflect.TypeOf(respTemplate)
	errorz.Assertf(respType.Kind() == reflect.Struct, "respTemplate must be a struct")

	return &jsonHTTPResponseMarshaler{
		respType: respType,
	}
}

// GetResponseType implements the HTTPResponseMarshaler interface.
func (m *jsonHTTPResponseMarshaler) GetResponseType() *reflect.Type {
	return &m.respType
}

// Marshal implements the HTTPResponseMarshaler interface.
func (m *jsonHTTPResponseMarshaler) Marshal(ctx context.Context, resp interface{}) *events.APIGatewayV2HTTPResponse {
	errorz.Assertf(resp != nil, "resp unexpectedly nil")
	respCtx := GetHTTPResponseContext(ctx)

	respCtx.headers.Set("Content-Type", "application/json; charset=utf-8")
	body := jsonz.MustMarshalIndentDefaultString(resp)

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

type jsonHTTPErrorMarshaler struct {
	marshaler HTTPResponseMarshaler
}

// NewJSONHTTPErrorMarshaler initializes a new HTTPErrorMarshaler.
func NewJSONHTTPErrorMarshaler() HTTPErrorMarshaler {
	return &jsonHTTPErrorMarshaler{
		marshaler: NewJSONHTTPResponseMarshaler(errorz.Summary{}),
	}
}

// Marshal implements the HTTPErrorMarshaler interface.
func (m *jsonHTTPErrorMarshaler) Marshal(ctx context.Context, err error) *events.APIGatewayV2HTTPResponse {
	respCtx := GetHTTPResponseContext(ctx)
	resp := errorz.ToSummary(err)

	if resp.Status == 0 {
		resp.Status = http.StatusInternalServerError
	}

	respCtx.SetStatus(resp.Status.Int())
	return m.marshaler.Marshal(ctx, resp)
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

	errorz.Assertf(requestUnmarshaler != nil, "requestUnmarshaler unexpectedly nil", errorz.Skip())
	errorz.Assertf(responseMarshaler != nil, "responseMarshaler unexpectedly nil", errorz.Skip())
	errorz.Assertf(errorMarshaler != nil, "errorMarshaler unexpectedly nil", errorz.Skip())
	errorz.Assertf(handlerFunc != nil, "handlerFunc unexpectedly nil", errorz.Skip())

	routeKey, err := ParseHTTPRouteKey(rawRouteKey)
	errorz.MaybeMustWrap(err, errorz.Skip())

	hfType := reflect.TypeOf(handlerFunc)
	errorz.Assertf(hfType.Kind() == reflect.Func, "handlerFunc must be a function", errorz.Skip())

	if reqType := requestUnmarshaler.GetRequestType(); reqType == nil {
		errorz.Assertf(hfType.NumIn() == 1 && hfType.In(0) == ctxType,
			"handlerFunc for a requestUnmarshaler with no request type must be func(context.Context) (...)", errorz.Skip())
	} else {
		errorz.Assertf(hfType.NumIn() == 2 && hfType.In(0) == ctxType && hfType.In(1) == reflect.PtrTo(*reqType),
			"handlerFunc for a requestUnmarshaler with request type T must be func(context.Context, *T) (...)", errorz.Skip())
	}

	if respType := responseMarshaler.GetResponseType(); respType == nil {
		errorz.Assertf(hfType.NumOut() == 1 && hfType.Out(0) == errType,
			"handlerFunc for a responseMarshaler with no response type must be func(...) error", errorz.Skip())
	} else {
		errorz.Assertf(hfType.NumOut() == 2 && hfType.Out(0) == reflect.PtrTo(*respType) && hfType.Out(1) == errType,
			"handlerFunc for a responseMarshaler with response type T must be func(...) (*T, error)", errorz.Skip())
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

func (e *HTTPEndpoint) handle(ctx context.Context) (resp interface{}, err error) {
	defer func() {
		if rErr := errorz.MaybeWrapRecover(recover()); rErr != nil {
			resp = nil
			err = rErr
		}
	}()

	if e.requestAuthorizer != nil {
		if err := e.requestAuthorizer.Authorize(ctx); err != nil {
			return nil, errorz.Wrap(err, errorz.Skip())
		}
	}

	req, err := e.requestUnmarshaler.Unmarshal(ctx)
	if err != nil {
		return nil, errorz.Wrap(err, errorz.Skip())
	}

	if e.requestUnmarshaler.GetRequestType() == nil {
		errorz.Assertf(req == nil, "req unexpectedly not nil", errorz.Skip())
	} else {
		errorz.Assertf(req != nil, "req unexpectedly nil", errorz.Skip())
	}

	resp, err = e.invoke(ctx, req)
	if err != nil {
		return nil, errorz.Wrap(err, errorz.Skip())
	}

	if e.responseMarshaler.GetResponseType() == nil {
		errorz.Assertf(resp == nil, "resp unexpectedly not nil", errorz.Skip())
		return nil, nil
	}

	errorz.Assertf(resp != nil, "resp unexpectedly nil", errorz.Skip())
	return resp, nil
}

func (e *HTTPEndpoint) invoke(ctx context.Context, req interface{}) (interface{}, error) {
	args := []reflect.Value{reflect.ValueOf(ctx)}
	if e.requestUnmarshaler.GetRequestType() != nil {
		args = append(args, reflect.ValueOf(req))
	}

	ret := reflect.ValueOf(e.handlerFunc).Call(args)

	vErr := ret[len(ret)-1]
	if err, ok := vErr.Interface().(error); ok && err != nil {
		return nil, errorz.Wrap(err, errorz.Skip())
	}

	if len(ret) > 1 {
		return ret[0].Interface(), nil
	}

	return nil, nil
}

// HTTPRouter implements a HTTP router.
type HTTPRouter struct {
	injector  injectz.Injector
	endpoints map[string]*HTTPEndpoint
}

// NewHTTPRouter initializes a new HTTPRouter.
func NewHTTPRouter() *HTTPRouter {
	return &HTTPRouter{
		endpoints: make(map[string]*HTTPEndpoint),
	}
}

// Register registers an endpoint.
func (r *HTTPRouter) Register(endpoint *HTTPEndpoint) *HTTPRouter {
	errorz.Assertf(r.endpoints[endpoint.routeKey.Raw] == nil, "route key already registered: %v", errorz.A(endpoint.routeKey.Raw), errorz.Skip())
	r.endpoints[endpoint.routeKey.Raw] = endpoint
	return r
}

// SetInjector sets the (optional) context injector.
func (r *HTTPRouter) SetInjector(injector injectz.Injector) *HTTPRouter {
	r.injector = injector
	return r
}

// GetEndpoints gets a slice of registered endpoints.
func (r *HTTPRouter) GetEndpoints() []*HTTPEndpoint {
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
func (r *HTTPRouter) Handler(ctx context.Context, event events.APIGatewayV2HTTPRequest) (hEvent events.APIGatewayV2HTTPResponse, hErr error) {
	ctx, finish := r.prepareContext(ctx, &event)
	defer finish()

	defer func() {
		if rErr := errorz.MaybeWrapRecover(recover()); rErr != nil {
			hEvent = events.APIGatewayV2HTTPResponse{}
			hErr = rErr
		}
		if hErr != nil {
			logz.Get(ctx).Error(hErr)
		}
	}()

	endpoint, ok := r.endpoints[event.RouteKey]
	if !ok {
		// Note: this is not really a "not found" - it is a misconfiguration between the router and he API.
		err := errorz.Errorf("unknown route key: %v", errorz.A(event.RouteKey), errorz.Skip())
		logz.Get(ctx).Error(err)
		return events.APIGatewayV2HTTPResponse{}, err
	}

	resp, err := endpoint.handle(ctx)
	if err != nil {
		logz.Get(ctx).Error(err)
		return *endpoint.errorMarshaler.Marshal(ctx, err), nil
	}

	return *endpoint.responseMarshaler.Marshal(ctx, resp), nil
}

// ShallowClone returns a shallow clone of the router.
func (r *HTTPRouter) ShallowClone() *HTTPRouter {
	endpoints := make(map[string]*HTTPEndpoint, len(r.endpoints))
	for k, v := range r.endpoints {
		endpoints[k] = v
	}
	return &HTTPRouter{
		injector:  r.injector,
		endpoints: endpoints,
	}
}

func (r *HTTPRouter) prepareContext(ctx context.Context, event *events.APIGatewayV2HTTPRequest) (context.Context, func()) {
	if r.injector != nil {
		ctx = r.injector(ctx)
	}

	ctx = context.WithValue(ctx, httpRequestContextKey, newHTTPRequestContext(event))
	ctx = context.WithValue(ctx, httpResponseContextKey, newHTTPResponseContext())

	routeKey, err := ParseHTTPRouteKey(event.RouteKey)
	if err != nil || routeKey.IsDefault {
		routeKey = &HTTPRouteKey{
			Raw:    event.RouteKey,
			Method: HTTPMethod(event.RequestContext.HTTP.Method),
			Path:   event.RequestContext.HTTP.Path,
		}
	}
	if routeKey.Method == Any {
		routeKey.Method = HTTPMethod(event.RequestContext.HTTP.Method)
	}

	ctx, release := logz.Get(ctx).TraceHTTPRequestServerSimple(&sentry.Request{
		URL:         routeKey.Path,
		Method:      routeKey.Method.String(),
		Data:        event.Body,
		QueryString: event.RawQueryString,
		Cookies: func() string {
			if len(event.Cookies) > 0 {
				return event.Cookies[0]
			}
			return ""
		}(),
		Headers: event.Headers,
		Env: map[string]string{
			"REMOTE_ADDR": event.RequestContext.HTTP.SourceIP,
		},
	})

	func() {
		defer func() {
			recover()
		}()

		logz.Get(ctx).AddMetadata("requestContext", event.RequestContext)
		logz.Get(ctx).AddMetadata("pathParameters", event.PathParameters)
		logz.Get(ctx).AddMetadata("stageVariables", event.StageVariables)
	}()

	return ctx, release
}
