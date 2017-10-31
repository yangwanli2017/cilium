package envoy

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/cilium/cilium/pkg/policy"
	"github.com/golang/protobuf/proto"

	log "github.com/sirupsen/logrus"
)

// Envoy manages a running Envoy proxy instance via the
// ListenerDiscoveryService and RouteDiscoveryService gRPC APIs.
type Envoy struct {
	cmd               *exec.Cmd
	LogPath           string
	AccessLogPath     string
	accessLogListener *net.UnixListener
	ldsSock           string
	lds               *LDSServer
	rdsSock           string
	rds               *RDSServer
}

type EnvoyLogger interface {
	Log(entry *HttpLogEntry)
}

func createConfig(filePath string, adminAddress string) {
	config := string("{\n" +
		"  \"listeners\": [],\n" +
		"  \"admin\": { \"access_log_path\": \"/dev/null\",\n" +
		"             \"address\": \"tcp://" + adminAddress + "\" },\n" +
		"  \"cluster_manager\": {\n" +
		"    \"clusters\": []\n" +
		"  }\n" +
		"}\n")

	log.Debug("Envoy: Configuration file: ", config)
	err := ioutil.WriteFile(filePath, []byte(config), 0644)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Failed writing configuration file ", filePath)
	}
}

// StartEnvoy starts an Envoy proxy instance. If 'debug' is true, an
// debug version of the Envoy binary is started with the log level
// 'debug', otherwise a production version is started at the default
// log level.
func StartEnvoy(debug bool, adminPort int, stateDir, logDir string) *Envoy {
	bootstrapPath := filepath.Join(stateDir, "bootstrap.pb")
	configPath := filepath.Join(stateDir, "envoy-config.json")
	logPath := filepath.Join(logDir, "cilium-envoy.log")
	adminAddress := "127.0.0.1:" + strconv.Itoa(adminPort)
	ldsPath := filepath.Join(stateDir, "lds.sock")
	rdsPath := filepath.Join(stateDir, "rds.sock")
	accessLogPath := filepath.Join(stateDir, "access_log.sock")

	e := &Envoy{LogPath: logPath, AccessLogPath: accessLogPath, ldsSock: ldsPath, rdsSock: rdsPath}

	// Create configuration
	createBootstrap(bootstrapPath, "envoy1", "cluster1", "version1",
		"ldsCluster", ldsPath, "rdsCluster", rdsPath, "cluster1")
	createConfig(configPath, adminAddress)

	e.StartAccessLogging(accessLogPath)

	if debug {
		e.cmd = exec.Command("sh", "-c", "cilium-envoy-debug >"+logPath+" 2>&1 -l debug -c "+configPath+" -b "+bootstrapPath)
	} else {
		e.cmd = exec.Command("sh", "-c", "cilium-envoy >"+logPath+" 2>&1 -c "+configPath+" -b "+bootstrapPath)
	}

	log.Debug("Envoy: Starting ", *e)

	e.lds = createLDSServer(ldsPath, accessLogPath)
	e.rds = createRDSServer(rdsPath, e.lds)
	e.rds.run()
	e.lds.run(e.rds)

	err := e.cmd.Start()
	if err != nil {
		log.WithError(err).Error("Envoy: Starting failed")
		return nil
	}
	log.Info("Envoy: Process started at pid ", e.cmd.Process.Pid)
	return e
}

// isEOF returns true if the error message ends in "EOF". ReadMsgUnix returns extra info in the beginning.
func isEOF(err error) bool {
	strerr := err.Error()
	errlen := len(strerr)
	return errlen >= 3 && strerr[errlen-3:] == io.EOF.Error()
}

// StopEnvoy kills the Envoy process started with StartEnvoy. The gRPC API streams are terminated
// first.
func (e *Envoy) StartAccessLogging(accessLogPath string) {
	// Create the access log listener
	os.Remove(accessLogPath)
	var err error
	e.accessLogListener, err = net.ListenUnix("unixpacket", &net.UnixAddr{Name: accessLogPath, Net: "unixpacket"})
	if err != nil {
		log.WithError(err).Fatal("Envoy: Failed to listen at ", accessLogPath)
	}
	e.accessLogListener.SetUnlinkOnClose(true)

	go func(uxlis *net.UnixListener) {
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := uxlis.AcceptUnix()
			if err != nil {
				log.WithError(err).Error("AcceptUnix failed")
				continue
			}
			log.Info("Envoy: Access log connection opened")
			go func(conn *net.UnixConn) {
				buf := make([]byte, 4096)
				for {
					n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
					if err != nil {
						if !isEOF(err) {
							log.WithError(err).Error("Envoy: Access log read error")
						}
						break
					}
					if flags&syscall.MSG_TRUNC != 0 {
						log.Warning("Envoy: Truncated access log message discarded.")
						continue
					}

					pblog := HttpLogEntry{}
					err = proto.Unmarshal(buf[:n], &pblog)
					if err != nil {
						log.WithError(err).Warning("Envoy: Invalid accesslog.proto HttpLogEntry message.")
						continue
					}

					// Correlate the log entry with a listener
					l := e.lds.findListener(pblog.CiliumResourceName)

					// Call the logger.
					if l != nil {
						l.logger.Log(&pblog)
					} else {
						log.Infof("Envoy: Orphan Access log message for %s: %s", pblog.CiliumResourceName, pblog.String())
					}
				}
				log.Info("Envoy: Access log closing")
				conn.Close()
			}(uc)
		}
	}(e.accessLogListener)
}

// StopEnvoy kills the Envoy process started with StartEnvoy. The gRPC API streams are terminated
// first.
func (e *Envoy) StopEnvoy() {
	log.Info("Envoy: Stopping process ", e.cmd.Process.Pid)
	e.rds.stop()
	e.lds.stop()
	err := e.cmd.Process.Kill()
	if err != nil {
		log.WithError(err).Fatal("Envoy: Stopping failed")
	}
	e.cmd.Wait()
}

// AddListener adds a listener to a running Envoy proxy.
func (e *Envoy) AddListener(name string, port uint16, l7rules policy.L7DataMap, isIngress bool, logger EnvoyLogger) {
	e.lds.addListener(name, port, l7rules, isIngress, logger)
}

// UpdateListener changes to the L7 rules of an existing Envoy Listener.
func (e *Envoy) UpdateListener(name string, l7rules policy.L7DataMap) {
	e.lds.updateListener(name, l7rules)
}

// RemoveListener removes an existing Envoy Listener.
func (e *Envoy) RemoveListener(name string) {
	e.lds.removeListener(name)
}
