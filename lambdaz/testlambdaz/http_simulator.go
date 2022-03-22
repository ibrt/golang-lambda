package testlambdaz

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/ibrt/golang-errors/errorz"
	"github.com/ibrt/golang-inject-http/httpz"
	"github.com/ibrt/golang-inject/injectz"
	"github.com/ibrt/golang-validation/vz"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"

	"github.com/ibrt/golang-lambda/lambdaz"
)

var (
	pathRegexp = regexp.MustCompile("{([a-zA-Z0-9]+)}")
)

// HTTPSimulatorConfig describes the HTTP simulator config.
type HTTPSimulatorConfig struct {
	Routes               map[string]*HTTPSimulatorConfigRoute               `json:"routes"`
	AWSProxyIntegrations map[string]*HTTPSimulatorConfigAWSProxyIntegration `json:"awsProxyIntegrations"`
}

// MustValidate validates the HTTPSimulatorConfig, panics on error.
func (c *HTTPSimulatorConfig) MustValidate() {
	errorz.MaybeMustWrap(vz.ValidateStruct(c))

	for _, route := range c.Routes {
		_, ok := c.AWSProxyIntegrations[route.IntegrationName]
		errorz.Assertf(ok, "unknown integration: %v", errorz.A(route.IntegrationName))
	}
}

// HTTPSimulatorConfigRoute describes part of the HTTP simulator config.
type HTTPSimulatorConfigRoute struct {
	IntegrationName string `json:"integrationName"`
}

// HTTPSimulatorConfigAWSProxyIntegration describes part of the HTTP simulator config.
type HTTPSimulatorConfigAWSProxyIntegration struct {
	URL string `json:"url" validate:"required,url"`
}

// HTTPSimulator provides a simplified implementation of an API Gateway v2 API for local testing purposes.
// Note that it has a lot of limitations:
// - Only AWS_PROXY integrations are supported.
// - Authorizers, transforms, etc. are not supported.
// - The ANY method, $default route, and {proxy+} routes are not supported.
// - Cookies are not handled.
type HTTPSimulator struct {
	cfg      *HTTPSimulatorConfig
	injector injectz.Injector
	e        *echo.Echo
}

// NewHTTPSimulator initializes a new HTTPSimulator.
func NewHTTPSimulator(cfg *HTTPSimulatorConfig, injector injectz.Injector) *HTTPSimulator {
	cfg.MustValidate()

	s := &HTTPSimulator{
		cfg:      cfg,
		injector: injector,
	}

	s.init()
	return s
}

// Run the simulator.
func (s *HTTPSimulator) Run(addr string) {
	go func() {
		if err := s.e.Start(addr); err != nil && err != http.ErrServerClosed {
			errorz.MustWrap(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errorz.MaybeMustWrap(s.e.Shutdown(ctx))
}

// GetEchoForTest returns the underlying Echo.
func (s *HTTPSimulator) GetEchoForTest() *echo.Echo {
	return s.e
}

func (s *HTTPSimulator) init() {
	s.e = echo.New()
	s.e.Debug = true
	s.e.Logger.SetLevel(log.DEBUG)
	s.e.Use(middleware.Logger())
	s.e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.SetRequest(c.Request().WithContext(s.injector(c.Request().Context())))
			return next(c)
		}
	})

	for rawRouteKey := range s.cfg.Routes {
		routeKey, err := lambdaz.ParseHTTPRouteKey(rawRouteKey)
		errorz.MaybeMustWrap(err)
		errorz.Assertf(!routeKey.IsDefault, "the $default route is not supported")
		errorz.Assertf(!strings.Contains(routeKey.Raw, "{proxy+}"), "{proxy+} routes are not supported")
		errorz.Assertf(routeKey.Method != lambdaz.Any, "the ANY method is not supported")

		s.e.Add(
			routeKey.Method.String(),
			pathRegexp.ReplaceAllString(routeKey.Path, ":$1"),
			s.handleEndpoint(routeKey))
	}
}

func (s *HTTPSimulator) handleEndpoint(routeKey *lambdaz.HTTPRouteKey) echo.HandlerFunc {
	return func(c echo.Context) error {
		return errorz.MaybeWrap(s.handle(c, routeKey))
	}
}

func (s *HTTPSimulator) handle(c echo.Context, routeKey *lambdaz.HTTPRouteKey) error {
	apiReq, err := s.parseAPIRequest(c, routeKey)
	if err != nil {
		return errorz.Wrap(err)
	}

	reqBuf, err := json.MarshalIndent(apiReq, "", "  ")
	if err != nil {
		return errorz.Wrap(err)
	}

	resp, err := httpz.Get(c.Request().Context()).Post(
		s.cfg.AWSProxyIntegrations[s.cfg.Routes[routeKey.Raw].IntegrationName].URL,
		"application/json; charset=UTF-8",
		bytes.NewReader(reqBuf))
	if err != nil {
		return errorz.Wrap(err)
	}
	defer errorz.IgnoreClose(resp.Body)

	respBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errorz.Wrap(err)
	}

	if resp.StatusCode != http.StatusOK {
		return errorz.Errorf("simulator: integration responded with %v: %v", errorz.A(resp.StatusCode, string(respBuf)))
	}

	apiResp := &events.APIGatewayV2HTTPResponse{}
	if err := json.Unmarshal(respBuf, apiResp); err != nil {
		return errorz.Wrap(err)
	}

	return errorz.MaybeWrap(s.writeAPIResponse(c, apiResp))
}

func (s *HTTPSimulator) parseAPIRequest(c echo.Context, routeKey *lambdaz.HTTPRouteKey) (events.APIGatewayV2HTTPRequest, error) {
	now := time.Now().UTC()
	body, isBase64Encoded, err := s.parseBody(c)
	if err != nil {
		return events.APIGatewayV2HTTPRequest{}, errorz.Wrap(err)
	}

	return events.APIGatewayV2HTTPRequest{
		Version:               "2.0",
		RouteKey:              routeKey.Raw,
		RawPath:               c.Request().URL.RawPath,
		RawQueryString:        c.Request().URL.RawQuery,
		Headers:               s.simplifyMap(c.Request().Header, true),
		QueryStringParameters: s.simplifyMap(c.Request().URL.Query(), false),
		PathParameters:        s.parsePathParams(c),
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RouteKey:     routeKey.Raw,
			AccountID:    "account-id",
			Stage:        "$default",
			RequestID:    "request-id",
			APIID:        "api-id",
			DomainName:   "api.execute-api.us-east-1.amazonaws.com",
			DomainPrefix: "api",
			Time:         now.Format("02/Jan/2006:15:04:05 -0700"),
			TimeEpoch:    now.Unix(),
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:    routeKey.Method.String(),
				Path:      c.Request().URL.RawPath,
				Protocol:  "HTTP/1.1",
				SourceIP:  c.Request().RemoteAddr,
				UserAgent: "agent",
			},
		},
		Body:            body,
		IsBase64Encoded: isBase64Encoded,
	}, nil
}

func (s *HTTPSimulator) writeAPIResponse(c echo.Context, apiResp *events.APIGatewayV2HTTPResponse) error {
	c.Response().Status = apiResp.StatusCode

	for k, vs := range apiResp.MultiValueHeaders {
		for _, v := range vs {
			c.Response().Header().Add(k, v)
		}
	}

	if len(apiResp.Body) > 0 {
		r := io.Reader(strings.NewReader(apiResp.Body))
		if apiResp.IsBase64Encoded {
			r = base64.NewDecoder(base64.StdEncoding, r)
		}
		if _, err := io.Copy(c.Response(), r); err != nil {
			return errorz.Wrap(err)
		}
	}

	c.Response().Flush()
	return nil
}

func (s *HTTPSimulator) parseBody(c echo.Context) (string, bool, error) {
	buf, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		return "", false, errorz.Wrap(err)
	}
	if len(buf) == 0 {
		return "", false, nil
	}
	return base64.StdEncoding.EncodeToString(buf), true, nil
}

func (s *HTTPSimulator) parsePathParams(c echo.Context) map[string]string {
	params := make(map[string]string, len(c.ParamNames()))
	for i, k := range c.ParamNames() {
		params[k] = c.ParamValues()[i]
	}
	return params
}

func (s *HTTPSimulator) simplifyMap(m map[string][]string, lowerCaseKeys bool) map[string]string {
	simplified := make(map[string]string, len(m))
	for k, vs := range m {
		if len(vs) > 0 {
			if lowerCaseKeys {
				k = strings.ToLower(k)
			}
			simplified[k] = vs[len(vs)-1]
		}
	}
	return simplified
}
