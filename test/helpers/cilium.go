// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helpers

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"

	log "github.com/sirupsen/logrus"
)

const (
	MaxRetries = 30
)

// ExecCilium runs a Cilium CLI command and returns the resultant cmdRes.
func (s *SSHMeta) ExecCilium(cmd string) *CmdRes {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	command := fmt.Sprintf("cilium %s", cmd)
	exit := s.ExecWithSudo(command, stdout, stderr)
	return &CmdRes{
		cmd:    command,
		stdout: stdout,
		stderr: stderr,
		exit:   exit,
	}
}

// EndpointGet returns the output of `cilium endpoint get` for the provided
// endpoint ID.
func (s *SSHMeta) EndpointGet(id string) *models.Endpoint {
	if id == "" {
		return nil
	}
	var data []models.Endpoint
	endpointGetCmd := fmt.Sprintf("endpoint get %s", id)
	res := s.ExecCilium(endpointGetCmd)
	err := res.Unmarshal(&data)
	if err != nil {
		s.logger.Errorf("EndpointGet fail %d: %s", id, err)
		return nil
	}
	if len(data) > 0 {
		return &data[0]
	}
	return nil
}

// EndpointSetConfig sets the provided configuration option to the provided
// value for the endpoint with the endpoint ID id.
func (s *SSHMeta) EndpointSetConfig(id, option, value string) bool {
	// TODO: GH-1725.
	// For now use `grep` with an extra space to ensure that we only match
	// on specified option.
	// TODO: for consistency, all fields should be constants if they are reused.
	logger := s.logger.WithFields(log.Fields{"EndpointId": id})
	res := s.ExecCilium(fmt.Sprintf(
		"endpoint config %s | grep '%s ' | awk '{print $2}'", id, option))

	if res.SingleOut() == value {
		logger.Debugf("no need to update %s=%s; value already set", option, value)
		return res.WasSuccessful()
	}

	before := s.EndpointGet(id)
	if before == nil {
		return false
	}
	configCmd := fmt.Sprintf("endpoint config %s %s=%s", id, option, value)
	data := s.ExecCilium(configCmd)
	if !data.WasSuccessful() {
		logger.Errorf("cannot set endpoint configuration %s=%s", option, value)
		return false
	}
	err := WithTimeout(func() bool {
		endpoint := s.EndpointGet(id)
		if endpoint == nil {
			return false
		}
		if len(endpoint.Status) > len(before.Status) {
			return true
		}
		logger.Info("endpoint not regenerated")
		return false
	}, "endpoint not regenerated", &TimeoutConfig{Timeout: 100})
	if err != nil {
		logger.Errorf("endpoint configuration update failed:%s", err)
		return false
	}
	return true
}

var EndpointWaitUntilReadyRetry int = 0 //List how many retries EndpointWaitUntilReady should have

// EndpointWaitUntilReady waits until all of the endpoints that Cilium manages
// are in 'ready' state.
func (s *SSHMeta) EndpointWaitUntilReady(validation ...bool) bool {

	logger := s.logger.WithFields(log.Fields{"EndpointWaitReady": ""})

	getEpsStatus := func(data []models.Endpoint) map[int64]int {
		result := make(map[int64]int)
		for _, v := range data {
			result[v.ID] = len(v.Status)
		}
		return result
	}

	var data []models.Endpoint

	if err := s.GetEndpoints().Unmarshal(&data); err != nil {
		if EndpointWaitUntilReadyRetry > MaxRetries {
			logger.Errorf("%d retries exceeded to get endpoints: %s", MaxRetries, err)
			return false
		}
		logger.Infof("cannot get endpoints: %s", err)
		logger.Info("sleeping 5 seconds and trying again to get endpoints")
		EndpointWaitUntilReadyRetry++
		Sleep(5)
		return s.EndpointWaitUntilReady(validation...)
	}
	EndpointWaitUntilReadyRetry = 0 //Reset to 0
	epsStatus := getEpsStatus(data)

	body := func() bool {
		var data []models.Endpoint

		if err := s.GetEndpoints().Unmarshal(&data); err != nil {
			logger.Infof("cannot get endpoints: %s", err)
			return false
		}
		var valid, invalid int
		for _, eps := range data {
			if eps.State != "ready" {
				invalid++
			} else {
				valid++
			}
			if len(validation) > 0 && validation[0] {
				// If the endpoint's latest statest message does not contain "Policy regeneration skipped", then it must be regenerating; wait until length of status message array changes.
				originalVal, _ := epsStatus[eps.ID]
				if !(len(eps.Status) > 0 && eps.Status[0].Message == "Policy regeneration skipped") && len(eps.Status) <= originalVal {
					logger.Infof("endpoint %d not regenerated", eps.ID)
					return false
				}
			}
		}

		if invalid == 0 {
			return true
		}

		logger.WithFields(log.Fields{
			"valid":   valid,
			"invalid": invalid,
		}).Info("endpoints not ready")

		return false
	}
	err := WithTimeout(body, "endpoints not ready", &TimeoutConfig{Timeout: 300})
	if err != nil {
		return false
	}
	return true
}

// GetEndpoints returns the CmdRes resulting from executing
// `cilium endpoint list -o json`.
func (s *SSHMeta) GetEndpoints() *CmdRes {
	return s.ExecCilium("endpoint list -o json")
}

// GetEndpointsIds returns a mapping of a Docker container name to to its
// corresponding endpoint ID, and an error if the list of endpoints cannot be
// retrieved via the Cilium CLI.
func (s *SSHMeta) GetEndpointsIds() (map[string]string, error) {
	// cilium endpoint list -o jsonpath='{range [*]}{@.container-name}{"="}{@.id}{"\n"}{end}'
	filter := `{range [*]}{@.container-name}{"="}{@.id}{"\n"}{end}`
	cmd := fmt.Sprintf("endpoint list -o jsonpath='%s'", filter)
	endpoints := s.ExecCilium(cmd)
	if !endpoints.WasSuccessful() {
		return nil, fmt.Errorf("%q failed: %s", cmd, endpoints.CombineOutput())
	}
	return endpoints.KVOutput(), nil
}

// GetEndpointsNames returns the container-name field of each Cilium endpoint.
func (s *SSHMeta) GetEndpointsNames() ([]string, error) {
	data := s.GetEndpoints()
	if data.WasSuccessful() == false {
		return nil, fmt.Errorf("`cilium endpoint get` was not successful")
	}
	result, err := data.Filter("{ [*].container-name }")
	if err != nil {
		return nil, err
	}

	return strings.Split(result.String(), " "), nil
}

// ManifestsPath returns the path of the directory where manifests (YAMLs
// containing policies, DaemonSets, etc.) are stored for the runtime tests.
// TODO: this can just be a constant; there's no need to have a function.
func (s *SSHMeta) ManifestsPath() string {
	return fmt.Sprintf("%s/runtime/manifests/", BasePath)
}

// GetFullPath returns the path of file name prepended with the absolute path
// where manifests (YAMLs containing policies, DaemonSets, etc.) are stored.
func (s *SSHMeta) GetFullPath(name string) string {
	return fmt.Sprintf("%s%s", s.ManifestsPath(), name)
}

// PolicyEndpointsSummary returns the count of whether policy enforcement is
// enabled, disabled, and the total number of endpoints, and an error if the
// Cilium endpoint metadata cannot be retrieved via the API.
func (s *SSHMeta) PolicyEndpointsSummary() (map[string]int, error) {
	result := map[string]int{
		Enabled:  0,
		Disabled: 0,
		Total:    0,
	}

	endpoints, err := s.GetEndpoints().Filter("{ [*].policy-enabled }")
	if err != nil {
		return result, fmt.Errorf("cannot get endpoints")
	}
	status := strings.Split(endpoints.String(), " ")
	result[Enabled], result[Total] = CountValues("true", status)
	result[Disabled], result[Total] = CountValues("false", status)
	return result, nil
}

// SetPolicyEnforcement sets the PolicyEnforcement configuration value for the
// Cilium agent to the provided status.
func (s *SSHMeta) SetPolicyEnforcement(status string, waitReady ...bool) *CmdRes {
	// We check before setting PolicyEnforcement; if we do not, EndpointWait
	// will fail due to the status of the endpoints not changing.
	log.Infof("setting PolicyEnforcement=%s", status)
	res := s.ExecCilium(fmt.Sprintf("config | grep %s | awk '{print $2}'", PolicyEnforcement))
	if res.SingleOut() == status {
		return res
	}
	res = s.ExecCilium(fmt.Sprintf("config %s=%s", PolicyEnforcement, status))
	if len(waitReady) > 0 && waitReady[0] {
		s.EndpointWaitUntilReady(true)
	}
	return res
}

// PolicyDelAll deletes all policy rules currently imported into Cilium.
func (s *SSHMeta) PolicyDelAll() *CmdRes {
	return s.PolicyDel("--all")
}

// PolicyDel deletes the policy with the given ID from Cilium.
func (s *SSHMeta) PolicyDel(id string) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("policy delete %s", id))
}

// PolicyGet runs `cilium policy get <id>`, where id is the name of a specific
// policy imported into Cilium. It returns the resultant CmdRes from running
// the aforementioned command.
func (s *SSHMeta) PolicyGet(id string) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("policy get %s", id))
}

// PolicyGetAll gets all policies that are imported in the Cilium agent.
func (s *SSHMeta) PolicyGetAll() *CmdRes {
	return s.ExecCilium("policy get")

}

// PolicyGetRevision retrieves the current policy revision number in the Cilium
// agent.
func (s *SSHMeta) PolicyGetRevision() (int, error) {
	//FIXME GH-1725
	rev := s.ExecCilium("policy get | grep Revision| awk '{print $2}'")
	return rev.IntOutput()
}

// PolicyImport imports a new policy into Cilium and waits until the policy
// revision number increments.
func (s *SSHMeta) PolicyImport(path string, timeout time.Duration) (int, error) {
	revision, err := s.PolicyGetRevision()
	if err != nil {
		return -1, fmt.Errorf("cannot get policy revision: %s", err)
	}
	s.logger.Infof("PolicyImport: %s and current policy revision is '%d'", path, revision)
	res := s.ExecCilium(fmt.Sprintf("policy import %s", path))
	if res.WasSuccessful() == false {
		s.logger.Errorf("could not import policy: %s", res.CombineOutput())
		return -1, fmt.Errorf("could not import policy %s", path)
	}
	body := func() bool {
		currentRev, _ := s.PolicyGetRevision()
		if currentRev > revision {
			s.PolicyWait(currentRev)
			return true
		}
		s.logger.Infof("PolicyImport: current revision %d same as %d", currentRev, revision)
		return false
	}
	err = WithTimeout(body, "could not import policy revision", &TimeoutConfig{Timeout: timeout})
	if err != nil {
		return -1, err
	}
	revision, err = s.PolicyGetRevision()
	s.logger.Infof("PolicyImport: finished %q with revision '%d'", path, revision)
	return revision, err
}

// PolicyWait executes `cilium policy wait`, which waits until all endpoints are
// updated to the given policy revision.
func (s *SSHMeta) PolicyWait(revisionNum int) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("policy wait %d", revisionNum))
}

// ReportFailed gathers relevant Cilium runtime data and logs for debugging
// purposes.
func (s *SSHMeta) ReportFailed(commands ...string) {
	wr := s.logger.Logger.Out
	fmt.Fprint(wr, "StackTrace Begin\n")

	//FIXME: Ginkgo PR383 add here --since option
	res := s.Exec("sudo journalctl --no-pager -u cilium")
	fmt.Fprint(wr, res.Output())

	fmt.Fprint(wr, "\n")
	res = s.ExecCilium("endpoint list")
	fmt.Fprint(wr, res.Output())

	for _, cmd := range commands {
		fmt.Fprintf(wr, "\nOutput of command '%s': \n", cmd)
		res = s.Exec(fmt.Sprintf("%s", cmd))
		fmt.Fprint(wr, res.Output())
	}
	fmt.Fprint(wr, "StackTrace Ends\n")
}

// ServiceAdd creates a new Cilium service with the provided ID, frontend,
// backends, and revNAT number. Returns the result of creating said service.
func (s *SSHMeta) ServiceAdd(id int, frontend string, backends []string, rev int) *CmdRes {
	cmd := fmt.Sprintf(
		"service update --frontend '%s' --backends '%s' --id '%d' --rev '%d'",
		frontend, strings.Join(backends, ","), id, rev)
	return s.ExecCilium(cmd)
}

// ServiceGet is a wrapper around `cilium service get <id>`. It returns the
// result of retrieving said service.
func (s *SSHMeta) ServiceGet(id int) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("service get '%d'", id))
}

// ServiceDel is a wrapper around `cilium service delete <id>`. It returns the
// result of deleting said service.
func (s *SSHMeta) ServiceDel(id int) *CmdRes {
	return s.ExecCilium(fmt.Sprintf("service delete '%d'", id))
}

// SetUpCilium sets up Cilium as a systemd service with a hardcoded set of options. It
// returns an error if any of the operations needed to start Cilium fails.
func (s *SSHMeta) SetUpCilium() error {
	template := `
PATH=/usr/lib/llvm-3.8/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
CILIUM_OPTS=--kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug
INITSYSTEM=SYSTEMD`

	err := RenderTemplateToFile("cilium", template, 0777)
	if err != nil {
		return err
	}
	defer os.Remove("cilium")

	res := s.Exec("sudo cp /vagrant/cilium /etc/sysconfig/cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	res = s.Exec("sudo systemctl restart cilium")
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	return nil
}

// WaitUntilReady waits until the output of `cilium status` returns with code
// zero. Returns an error if the output of `cilium status` returns a nonzero
// return code after the specified timeout duration has elapsed.
func (s *SSHMeta) WaitUntilReady(timeout time.Duration) error {

	body := func() bool {
		res := s.ExecCilium("status")
		s.logger.Infof("Cilium status is %t", res.WasSuccessful())
		return res.WasSuccessful()
	}
	err := WithTimeout(body, "Cilium is not ready", &TimeoutConfig{Timeout: timeout})
	return err
}
