package lambdaz_test

import (
	"testing"

	"github.com/ibrt/golang-fixtures/fixturez"
	"github.com/ibrt/golang-inject-logs/logz/testlogz"
)

type Suite struct {
	*fixturez.DefaultConfigMixin
	Logs *testlogz.MockHelper
}

func TestHTTPRouter(t *testing.T) {
	fixturez.RunSuite(t, &Suite{})
}
