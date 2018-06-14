package rules

import (
	"fmt"
	"testing"

	"github.com/prometheus/prometheus/pkg/labels"
)

func TestNewAlertTestRule(t *testing.T) {

	str := `
	{
	   "alert_name" : "probe_success_network_icmp",
	   "test_expr" : "(go_goroutines{instance=\"localhost:9090\",job=\"prometheus\"}) > 30",
       "label_sets": [
          {
			"instance": "localhost:9090", 
			"job": "prometheus"
		  }
	   ]
	}
	`

	atr, err := NewAlertRuleTest([]byte(str))
	if err != nil {
		fmt.Println(err)
	}

	if atr.AlertName != "probe_success_network_icmp" {
		t.Fail()
	}

	if atr.TestExpr != "(go_goroutines{instance=\"localhost:9090\",job=\"prometheus\"}) > 30" {
		t.Fail()
	}

	for _, inst := range atr.instances {
		if inst.Get("instance") != "localhost:9090" {
			t.Fail()
		}
		if inst.Get("job") != "prometheus" {
			t.Fail()
		}
	}
}

func TestAddAlertTestRule(t *testing.T) {
	str := `
	{
	   "alert_name" : "probe_success_network_icmp",
	   "test_expr" : "(go_goroutines{instance=\"localhost:9090\",job=\"prometheus\"}) > 30",
       "label_sets": [
          {
			"instance": "localhost:9090", 
			"job": "prometheus"
		  }
	   ]
	}
	`

	err := AddAlertTestRule([]byte(str))
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}

	atr, _ := testpool.Get("probe_success_network_icmp")

	if atr.AlertName != "probe_success_network_icmp" {
		t.Fail()
	}

	if atr.TestExpr != "(go_goroutines{instance=\"localhost:9090\",job=\"prometheus\"}) > 30" {
		t.Fail()
	}

	for _, inst := range atr.instances {
		if inst.Get("instance") != "localhost:9090" {
			t.Fail()
		}
		if inst.Get("job") != "prometheus" {
			t.Fail()
		}
	}
}

func TestMatch(t *testing.T) {
	str := `
	{
	   "alert_name" : "probe_success_network_icmp",
	   "test_expr" : "(go_goroutines{instance=\"localhost:9090\",job=\"prometheus\"}) > 30",
       "label_sets": [
          {
			"instance": "localhost:9090", 
			"job": "prometheus"
		  }
	   ]
	}
	`

	err := AddAlertTestRule([]byte(str))
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	atr, _ := testpool.Get("probe_success_network_icmp")

	m := make(map[string]string)
	m["job"] = "prometheus"
	m["instance"] = "localhost:9090"

	lbs := labels.FromMap(m)

	if !atr.Match(lbs) {
		t.Fail()
	}
}
