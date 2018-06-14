package rules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/go-kit/kit/log/level"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/go-kit/kit/log"

	yaml "gopkg.in/yaml.v2"
)

type KVPair struct {
	// Key is the name of the key. It is also part of the URL path when accessed
	// via the API.
	Key string

	// CreateIndex holds the index corresponding the creation of this KVPair. This
	// is a read-only field.
	CreateIndex uint64

	// ModifyIndex is used for the Check-And-Set operations and can also be fed
	// back into the WaitIndex of the QueryOptions in order to perform blocking
	// queries.
	ModifyIndex uint64

	// LockIndex holds the index corresponding to a lock on this key, if any. This
	// is a read-only field.
	LockIndex uint64

	// Flags are any user-defined flags on the key. It is up to the implementer
	// to check these values, since Consul does not treat them specially.
	Flags uint64

	// Value is the value for the key. This can be any value, but it will be
	// base64 encoded upon transport.
	Value []byte

	// Session is a string representing the ID of the session. Any other
	// interactions with this key over the same session must specify the same
	// session ID.
	Session string
}

// type KVPairs []*KVPair

const TestMgrConfigFile = "testmgr.yml"

var (
	tmCfg *Config

	logger log.Logger

	alertRuleTestChangeTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "alert_rule_test_change_total",
			Help: "The total times of alert rule test changes.",
		},
	)

	quit      = make(chan struct{})
	startOnce sync.Once
	stopOnce  sync.Once
)

func init() {
	prometheus.MustRegister(alertRuleTestChangeTotal)
}

func startSync(log log.Logger) {
	startOnce.Do(func() {
		logger = log
		initSync()
		go listenChanges()
	})
}

func stopSync() {
	stopOnce.Do(func() {
		close(quit)
	})
}

func initSync() {
	level.Info(logger).Log("msg", "Starting testmgr synchronizer...")
	cfg, err := LoadFile(TestMgrConfigFile)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to load configuration for alert rule test manager.", "err", err)
		return
	}
	tmCfg = cfg

	arts, err := loadAlertRuleTests()
	if err != nil {
		level.Error(logger).Log("msg", "Failed to load all alert rule tests. ", "err", err)
		return
	}
	testpool.Refresh(arts)
	level.Info(logger).Log("msg", "Testmgr synchronizer is initialized.")
}

//Loads the silence instances from Consul
func loadAlertRuleTests() ([]*AlertRuleTest, error) {

	resp, err := http.Get(tmCfg.SyncURL + "?recurse=true")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return processResponse(resp)
}

//ListenChanges is called by alert rule test change listener goroutine
func listenChanges() {
	level.Info(logger).Log("msg", "Testmgr synchronizer is started.")
	index := ""
	for {
		select {
		case <-quit:
			level.Info(logger).Log("msg", "Testmgr synchronizer is stopped.")
			return
		default:
		}

		level.Debug(logger).Log("msg", "Blocking on AlertRuleTest Changes index="+index)
		i, ss, err := listenAlertRuleTestChanges(index)
		if err != nil {
			level.Error(logger).Log("msg", fmt.Sprintf("Failed to listen AlertRuleTest Changes index=%s, error=%s", index, err))
			num := rand.Int31n(30)
			time.Sleep(time.Duration(num) * time.Second)
			index = "" //Reset index
			continue
		}
		level.Debug(logger).Log("msg", fmt.Sprintf("Got AlertRuleTest Changes index=%s, new index=%s", index, i))
		index = i
		if ss == nil {
			level.Debug(logger).Log("msg", "No data loaded for AlertRuleTest Changes notification.")
			continue
		}

		testpool.Refresh(ss)
		alertRuleTestChangeTotal.Inc()
	}

}

//ListenSilenceChanges returns the
func listenAlertRuleTestChanges(lastIndex string) (string, []*AlertRuleTest, error) {
	url := tmCfg.SyncURL + "?recurse=true&index=" + lastIndex
	resp, err := http.Get(url)
	if err != nil {
		return lastIndex, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return lastIndex,
			nil,
			fmt.Errorf("error to get URL=%s, status code=%d; Please check if the key=AlertRuleTests exists in the Consul KV or not", url, resp.StatusCode)
	}

	index := resp.Header.Get("x-consul-index")
	if index == "" || index == lastIndex {
		return lastIndex, nil, err
	}

	ss, err := processResponse(resp)

	return index, ss, err
}

func processResponse(resp *http.Response) ([]*AlertRuleTest, error) {
	r, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	kvpairs := []*KVPair{}

	if err := json.Unmarshal(r, &kvpairs); err != nil {
		return nil, err
	}

	tests := []*AlertRuleTest{}
	var test *AlertRuleTest

	for _, kvp := range kvpairs {
		if kvp.Value == nil {
			continue
		}
		test, err = NewAlertRuleTest(kvp.Value)
		if err != nil {
			continue
		}

		tests = append(tests, test)
	}
	return tests, nil
}

type Config struct {
	SyncURL  string `yaml:"sync_url"`
	original string
}

func load(s string) (*Config, error) {
	cfg := &Config{SyncURL: "http://127.0.0.1:8500", original: "test"}

	err := yaml.Unmarshal([]byte(s), cfg)
	if err != nil {
		return nil, err
	}
	cfg.original = s
	return cfg, nil
}

// LoadFile parses the given YAML file into a Config.
func LoadFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg, err := load(string(content))
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
