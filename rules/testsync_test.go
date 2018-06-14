package rules

import (
	"testing"
)

func TestLoadFile(t *testing.T) {

	cfg, _ := LoadFile(TestMgrConfigFile)

	if cfg.SyncURL != "http://10.99.70.35:8500/api/v1/kv/BU/jishubaozhangbu/Project/prometheus/Service/prometheus/alertruletests/" {
		t.Fail()
	}

}

func TestLoadAlertRuleTests(t *testing.T) {
	initSync()
	arts, _ := loadAlertRuleTests()

	if len(arts) != 1 {
		t.Fail()
	}
}
