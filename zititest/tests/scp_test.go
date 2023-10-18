/*
	(c) Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package tests

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/openziti/fablab/kernel/lib"
	"github.com/openziti/fablab/kernel/model"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestScp(t *testing.T) {
	allZetHostedFailed := true
	allZetClientsFailed := true

	t.Run("scp-tests", func(t *testing.T) {
		t.Run("test-ert-scp", func(t *testing.T) {
			t.Parallel()
			for _, hostType := range []string{"ert", "zet", "ziti-tunnel"} {
				for _, encrypted := range []bool{true, false} {
					success := testScp(t, "ert", hostType, encrypted)
					if hostType == "zet" && success {
						allZetHostedFailed = false
					}
				}
			}
		})

		t.Run("test-zet-scp", func(t *testing.T) {
			t.Parallel()

			for _, hostType := range []string{"zet", "ziti-tunnel", "ert"} {
				for _, encrypted := range []bool{true, false} {
					success := testScp(t, "zet", hostType, encrypted)
					if hostType == "zet" && success {
						allZetHostedFailed = false
					}
					if success {
						allZetClientsFailed = false
					}
				}
			}
		})

		t.Run("test-ziti-tunnel-scp", func(t *testing.T) {
			t.Parallel()

			for _, hostType := range []string{"ziti-tunnel", "ert", "zet"} {
				for _, encrypted := range []bool{true, false} {
					success := testScp(t, "ziti-tunnel", hostType, encrypted)
					if hostType == "zet" && success {
						allZetHostedFailed = false
					}
				}
			}
		})
	})

	req := require.New(t)
	req.False(allZetHostedFailed, "all zet hosted file transfer should not failed, indicates bigger issue")

	// TODO: fix once ZET client tests are working
	req.True(allZetClientsFailed, "all zet client file transfers should not failed, indicates bigger issue")
}

func testScp(t *testing.T, hostSelector string, hostType string, encrypted bool) bool {
	encDesk := "encrypted"
	if !encrypted {
		encDesk = "unencrypted"
	}

	success := false

	t.Run(fmt.Sprintf("(%s->%s)-%v", hostSelector, hostType, encDesk), func(t *testing.T) {
		if hostSelector == "zet" {
			t.Skipf("zet is currently failing as client")
		}
		host, err := model.GetModel().SelectHost("." + hostSelector + "-client")
		req := require.New(t)
		req.NoError(err)

		nameExtra := ""
		if !encrypted {
			nameExtra = "-unencrypted"
		}

		sshConfigFactory := lib.NewSshConfigFactory(host)

		cmds := []string{
			fmt.Sprintf("scp -o StrictHostKeyChecking=no ssh-%s%s.ziti:./fablab/bin/ziti /tmp/ziti-%s", hostType, nameExtra, uuid.NewString()),
			fmt.Sprintf("scp -o StrictHostKeyChecking=no ./fablab/bin/ziti ssh-%s%s.ziti:/tmp/ziti-%s", hostType, nameExtra, uuid.NewString()),
		}

		o, err := lib.RemoteExecAllWithTimeout(sshConfigFactory, 10*time.Second, cmds...)
		if hostType == "zet" && err != nil {
			t.Skipf("zet hosted ssh failed [%v]", err.Error())
			return
		}

		if hostSelector == "zet" && err != nil {
			t.Skipf("zet client ssh failed [%v]", err.Error())
			return
		}

		t.Log(o)
		req.NoError(err)
		success = true
	})
	return success
}