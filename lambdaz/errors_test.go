package lambdaz_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ibrt/golang-errors/errorz"
	"github.com/stretchr/testify/require"

	"github.com/ibrt/golang-lambda/lambdaz"
)

func TestErrBadRequest(t *testing.T) {
	err := lambdaz.NewErrBadRequest("test error", errorz.Prefix("test prefix"))
	require.Error(t, err)
	require.Equal(t, "bad request: test prefix: test error", err.Error())
	require.Equal(t, "bad-request", errorz.GetID(err).String())
	require.Equal(t, http.StatusBadRequest, errorz.GetStatus(err).Int())
	require.True(t, strings.HasPrefix(errorz.FormatStackTrace(errorz.GetCallers(err))[0], "lambdaz_test.TestErrBadRequest"))

	err = lambdaz.WrapErrBadRequest(errorz.Errorf("test error"), errorz.Prefix("test prefix"))
	require.Error(t, err)
	require.Equal(t, "bad request: test prefix: test error", err.Error())
	require.Equal(t, "bad-request", errorz.GetID(err).String())
	require.Equal(t, http.StatusBadRequest, errorz.GetStatus(err).Int())
	require.True(t, strings.HasPrefix(errorz.FormatStackTrace(errorz.GetCallers(err))[0], "lambdaz_test.TestErrBadRequest"))
	require.Equal(t, lambdaz.WrapErrBadRequest(err), err)

	err = lambdaz.WrapErrBadRequest(errorz.Errorf("test error", errorz.ID("test-id")))
	require.Error(t, err)
	require.Equal(t, "bad request: test error", err.Error())
	require.Equal(t, "test-id", errorz.GetID(err).String())
	require.Equal(t, http.StatusBadRequest, errorz.GetStatus(err).Int())
	require.True(t, strings.HasPrefix(errorz.FormatStackTrace(errorz.GetCallers(err))[0], "lambdaz_test.TestErrBadRequest"))
	require.Equal(t, lambdaz.WrapErrBadRequest(err), err)
}

func TestErrUnauthorized(t *testing.T) {
	err := lambdaz.NewErrUnauthorized("test error", errorz.Prefix("test prefix"))
	require.Error(t, err)
	require.Equal(t, "unauthorized: test prefix: test error", err.Error())
	require.Equal(t, "unauthorized", errorz.GetID(err).String())
	require.Equal(t, http.StatusUnauthorized, errorz.GetStatus(err).Int())
	require.True(t, strings.HasPrefix(errorz.FormatStackTrace(errorz.GetCallers(err))[0], "lambdaz_test.TestErrUnauthorized"))

	err = lambdaz.WrapErrUnauthorized(errorz.Errorf("test error"), errorz.Prefix("test prefix"))
	require.Error(t, err)
	require.Equal(t, "unauthorized: test prefix: test error", err.Error())
	require.Equal(t, "unauthorized", errorz.GetID(err).String())
	require.Equal(t, http.StatusUnauthorized, errorz.GetStatus(err).Int())
	require.True(t, strings.HasPrefix(errorz.FormatStackTrace(errorz.GetCallers(err))[0], "lambdaz_test.TestErrUnauthorized"))
	require.Equal(t, lambdaz.WrapErrUnauthorized(err), err)

	err = lambdaz.WrapErrUnauthorized(errorz.Errorf("test error", errorz.ID("test-id")))
	require.Error(t, err)
	require.Equal(t, "unauthorized: test error", err.Error())
	require.Equal(t, "test-id", errorz.GetID(err).String())
	require.Equal(t, http.StatusUnauthorized, errorz.GetStatus(err).Int())
	require.True(t, strings.HasPrefix(errorz.FormatStackTrace(errorz.GetCallers(err))[0], "lambdaz_test.TestErrUnauthorized"))
	require.Equal(t, lambdaz.WrapErrUnauthorized(err), err)
}

func TestErrForbidden(t *testing.T) {
	err := lambdaz.NewErrForbidden("test error", errorz.Prefix("test prefix"))
	require.Error(t, err)
	require.Equal(t, "forbidden: test prefix: test error", err.Error())
	require.Equal(t, "forbidden", errorz.GetID(err).String())
	require.Equal(t, http.StatusForbidden, errorz.GetStatus(err).Int())
	require.True(t, strings.HasPrefix(errorz.FormatStackTrace(errorz.GetCallers(err))[0], "lambdaz_test.TestErrForbidden"))

	err = lambdaz.WrapErrForbidden(errorz.Errorf("test error"), errorz.Prefix("test prefix"))
	require.Error(t, err)
	require.Equal(t, "forbidden: test prefix: test error", err.Error())
	require.Equal(t, "forbidden", errorz.GetID(err).String())
	require.Equal(t, http.StatusForbidden, errorz.GetStatus(err).Int())
	require.True(t, strings.HasPrefix(errorz.FormatStackTrace(errorz.GetCallers(err))[0], "lambdaz_test.TestErrForbidden"))
	require.Equal(t, lambdaz.WrapErrForbidden(err), err)

	err = lambdaz.WrapErrForbidden(errorz.Errorf("test error", errorz.ID("test-id")))
	require.Error(t, err)
	require.Equal(t, "forbidden: test error", err.Error())
	require.Equal(t, "test-id", errorz.GetID(err).String())
	require.Equal(t, http.StatusForbidden, errorz.GetStatus(err).Int())
	require.True(t, strings.HasPrefix(errorz.FormatStackTrace(errorz.GetCallers(err))[0], "lambdaz_test.TestErrForbidden"))
	require.Equal(t, lambdaz.WrapErrForbidden(err), err)
}
