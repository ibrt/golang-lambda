package main

import (
	"encoding/json"
	"flag"

	"github.com/ibrt/golang-bites/filez"
	"github.com/ibrt/golang-errors/errorz"
	"github.com/ibrt/golang-inject-http/httpz"
	"github.com/ibrt/golang-inject/injectz"

	"github.com/ibrt/golang-lambda/lambdaz/testlambdaz"
)

var (
	cfgFilePathFlag = flag.String("f", "", "path to simulator config file")
	listenAddrFlag  = flag.String("l", "", "listen address, e.g. ':3000'")
)

func main() {
	flag.Parse()
	errorz.Assertf(cfgFilePathFlag != nil && *cfgFilePathFlag != "", "missing flag -f")
	errorz.Assertf(listenAddrFlag != nil && *listenAddrFlag != "", "missing flag -l")

	cfg := &testlambdaz.HTTPSimulatorConfig{}
	errorz.MaybeMustWrap(json.Unmarshal(filez.MustReadFile(*cfgFilePathFlag), cfg))

	injector, releaser := injectz.Initialize(httpz.Initializer)
	defer releaser()
	testlambdaz.NewHTTPSimulator(cfg, injector).Run(*listenAddrFlag)
}
