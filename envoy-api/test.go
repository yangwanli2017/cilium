package main

import (
	"time"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	log "github.com/sirupsen/logrus"
)

type testRedirect struct {
	name string
}

func (t *testRedirect) Log(pblog *envoy.HttpLogEntry) {
	log.Infof("%s/%s: Access log message: %s", t.name, pblog.CiliumResourceName, pblog.String())
}

func main() {
	log.SetLevel(log.DebugLevel)

	// launch debug variant of the Envoy proxy
	Envoy := envoy.StartEnvoy(true, 9901, "", "")

	sel := api.NewWildcardEndpointSelector()

	Envoy.AddListener("listener1", 8081, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Path: "foo"},
			{Method: "POST"},
			{Host: "cilium"},
			{Headers: []string{"via"}}}}},
		true, &testRedirect{name: "listener1"})
	Envoy.AddListener("listener2", 8082, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via", "x-foo: bar"}}}}},
		true, &testRedirect{name: "listener2"})
	Envoy.AddListener("listener3", 8083, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: ".*public"}}}},
		false, &testRedirect{name: "listener3"})

	time.Sleep(600 * time.Millisecond)

	// Update listener2
	Envoy.UpdateListener("listener2", policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via: home", "x-foo: bar"}}}}})

	time.Sleep(300 * time.Millisecond)

	// Update listener1
	Envoy.UpdateListener("listener1", policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via"}}}}})

	time.Sleep(300 * time.Millisecond)

	// Remove listerner3
	Envoy.RemoveListener("listener3")

	time.Sleep(300 * time.Millisecond)

	// Add listener3 again
	Envoy.AddListener("listener3", 8083, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: ".*public"}}}},
		false, &testRedirect{name: "listener3"})

	time.Sleep(300 * time.Millisecond)

	// Remove listerner3 again
	Envoy.RemoveListener("listener3")

	time.Sleep(10000 * time.Millisecond)

	Envoy.StopEnvoy()

	time.Sleep(10000 * time.Millisecond)
}
