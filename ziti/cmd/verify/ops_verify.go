package verify

import (
	"fmt"
	"github.com/openziti/ziti/common"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"strings"
	"time"
)

type VerifyNetwork struct {
	controllerConfig string
	routerConfig     string
}

func NewVerifyNetwork() *cobra.Command {
	v := &VerifyNetwork{}

	cmd := &cobra.Command{
		Use:   "verify-network",
		Short: "Verifies the overlay is configured correctly",
		Long:  "A tool to verify network configurations, checking controller and router ports or other common problems",
		Run: func(cmd *cobra.Command, args []string) {
			anyFailure := false
			if v.controllerConfig != "" {
				logInfo("Verifying controller config: " + v.controllerConfig)
				anyFailure = verifyControllerConfig(v.controllerConfig) || anyFailure
				fmt.Println()
			}
			if v.routerConfig != "" {
				logInfo("Verifying router config: " + v.routerConfig)
				anyFailure = verifyRouterConfig(v.routerConfig) || anyFailure
				fmt.Println()
			}
			if anyFailure {
				logErr("One or more error. Review the output above for errors.")
			} else {
				logInfo("All requested checks passed.")
			}
		},
	}

	cmd.Flags().StringVarP(&v.controllerConfig, "controller-config-file", "c", "", "the controller config file verify")
	cmd.Flags().StringVarP(&v.routerConfig, "router-config-file", "r", "", "the router config file to verify")
	cmd.Flags().StringVarP(&v.identityFile, "identity", "i", "", "the identity file to use to verify the network")

	return cmd
}

type StringMap map[string]interface{}

func (m StringMap) mapFromKey(key string) StringMap {
	if v, ok := m[key]; ok {
		return v.(StringMap)
	}
	logrus.Fatalf("map didn't contain key %s", key)
	return nil
}

type StringMapList []interface{}

func (m StringMap) listFromKey(key string) StringMapList {
	if v, ok := m[key]; ok {
		return v.([]interface{})
	}
	logrus.Fatalf("map didn't contain key %s", key)
	return nil
}

func (p ProtoHostPort) testPort(msg string) bool {
	conn, err := net.DialTimeout("tcp", p.address(), 3*time.Second)
	if err != nil {
		logErr(fmt.Sprintf("%s at %s cannot be reached.", msg, p.address()))
		return true
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)
	logInfo(fmt.Sprintf("%s at %s is available.", msg, p.address()))
	return false
}

type ProtoHostPort struct {
	proto string
	host  string
	port  string
}

func (p ProtoHostPort) address() string {
	return p.host + ":" + p.port
}

func fromString(input string) *ProtoHostPort {
	// input is expected to be in either "proto:host:port" format or "host:port" format
	r := new(ProtoHostPort)
	parts := strings.Split(input, ":")
	if len(parts) > 2 {
		r.proto = parts[0]
		r.host = parts[1]
		r.port = parts[2]
	} else if len(parts) > 1 {
		r.proto = "none"
		r.host = parts[0]
		r.port = parts[1]
	} else {
		panic("input is invalid: " + input)
	}
	return r
}

func verifyControllerConfig(controllerConfigFile string) bool {
	if _, err := os.Stat(controllerConfigFile); err != nil {
		logErr(fmt.Sprintf("controller config file %s does not exist", controllerConfigFile))
		return true
	}
	ctrlCfgBytes, err := os.ReadFile(controllerConfigFile)
	if err != nil {
		panic(err)
	}
	ctrlCfg := make(StringMap)
	err = yaml.Unmarshal(ctrlCfgBytes, &ctrlCfg)
	if err != nil {
		panic(err)
	}
	advertiseAddress := stringOrNil(ctrlCfg.mapFromKey("ctrl").mapFromKey("options")["advertiseAddress"])
	host := fromString(advertiseAddress)
	anyFailure := host.testPort("controller advertise address")

	web := ctrlCfg.listFromKey("web")

	logInfo(fmt.Sprintf("verifying %d web entries", len(web)))
	for _, item := range web {
		webEntry := item.(StringMap)
		webName := stringOrNil(webEntry["name"])
		bps := webEntry.listFromKey("bindPoints")
		logInfo(fmt.Sprintf("verifying %d web bindPoints", len(bps)))
		bpPos := 0
		for _, bpItem := range bps {
			bp := bpItem.(StringMap)
			bpInt := fromString(stringOrNil(bp["interface"]))
			bpAddr := fromString(stringOrNil(bp["address"]))
			if bpInt.port != bpAddr.port {
				logWarn(fmt.Sprintf("web entry[%s], bindPoint[%d] ports differ. make sure this is intentional. interface port: %s, address port: %s", webName, bpPos, bpInt.port, bpAddr.port))
			}

			if bpAddr.testPort(fmt.Sprintf("web entry[%s], bindPoint[%d] %s", webName, bpPos, "address")) {
				anyFailure = true
			} else {
				logInfo(fmt.Sprintf("web entry[%s], bindPoint[%d] is valid", webName, bpPos))
			}
			bpPos++
		}
	}
	return anyFailure
}

func verifyRouterConfig(routerConfigFile string) bool {
	if _, err := os.Stat(routerConfigFile); err != nil {
		logErr(fmt.Sprintf("router config file %s does not exist", routerConfigFile))
		return true
	}
	routerCfg := make(StringMap)
	routerCfgBytes, err := os.ReadFile(routerConfigFile)
	err = yaml.Unmarshal(routerCfgBytes, &routerCfg)
	if err != nil {
		panic(err)
	}

	controllerEndpoint := stringOrNil(routerCfg.mapFromKey("ctrl")["endpoint"])
	routerCtrl := fromString(controllerEndpoint)
	anyFailure := routerCtrl.testPort("ctrl endpoint")

	link := routerCfg.mapFromKey("link")
	linkListeners := link.listFromKey("listeners")
	logInfo(fmt.Sprintf("verifying %d web link listeners", len(linkListeners)))
	pos := 0
	for _, item := range linkListeners {
		listener := item.(StringMap)
		if verifyLinkListener(fmt.Sprintf("link listener[%d]", pos), listener) {
			anyFailure = true
		} else {
			logInfo(fmt.Sprintf("link listener[%d] is valid", pos))
		}
		pos++
	}

	edgeListeners := routerCfg.listFromKey("listeners")
	logInfo(fmt.Sprintf("verifying %d web edge listeners", len(edgeListeners)))
	pos = 0
	for _, item := range edgeListeners {
		listener := item.(StringMap)
		if verifyEdgeListener(fmt.Sprintf("listener binding[%d]", pos), listener) {
			anyFailure = true
		} else {
			logInfo(fmt.Sprintf("listener binding[%d] is valid", pos))
		}
		pos++
	}
	return anyFailure
}

func logInfo(msg string) {
	log("INFO :", msg)
}
func logWarn(msg string) {
	log("WARN :", msg)
}
func logErr(msg string) {
	log("ERROR:", msg)
}
func log(level string, msg string) {
	fmt.Printf("%s %s\n", level, msg)
}
func stringOrNil(input interface{}) string {
	if str, ok := input.(string); ok {
		return str
	}
	return ""
}

func verifyLinkListener(which string, listener StringMap) bool {
	bind := fromString(stringOrNil(listener["bind"]))
	adv := fromString(stringOrNil(listener["advertise"]))
	if bind.port != adv.port {
		logWarn(fmt.Sprintf("%s ports differ. make sure this is intentional. bind port: %s, advertise port: %s", which, bind.port, adv.port))
	}
	return adv.testPort(which)
}

func verifyEdgeListener(which string, listener StringMap) bool {
	binding := stringOrNil(listener["binding"])
	if binding == common.EdgeBinding {
		address := stringOrNil(listener["address"])
		opts := listener.mapFromKey("options")
		advertise := stringOrNil(opts["advertise"])

		add := fromString(address)
		adv := fromString(advertise)
		if add.port != adv.port {
			logWarn(fmt.Sprintf("%s ports differ. make sure this is intentional. address port: %s, advertise port: %s", which, add.port, adv.port))
		}
		return adv.testPort(which)
	} else {
		// only verify "edge" for now
		logInfo(fmt.Sprintf("%s has binding %s and doesn't need to be verified", which, binding))
	}
	return false
}
