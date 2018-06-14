package rules

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql"
)

func appendTestRes(ctx context.Context, alertname string, ts time.Time, engine *promql.Engine, res promql.Vector) promql.Vector {

	//Get expr, instances by alertname
	atr, ok := testpool.Get(alertname)
	if !ok {
		return res
	}

	expr := atr.TestExpr //`(go_goroutines{instance="localhost:9090",job="prometheus"}) > 10`

	query, err := engine.NewInstantQuery(expr, ts)
	if err != nil {
		return res
	}
	res1, err := query.Exec(ctx).Vector()
	if err != nil {
		return res
	}

	for _, s := range res1 {

		//filter by instances
		if !atr.Match(s.Metric) {
			continue
		}

		builder := labels.NewBuilder(s.Metric)
		builder.Set("mode", "test")
		a := builder.Labels()
		//		res1[i].Metric = a     since s is only a copy of res1[i], update s would not update res1.
		s.Metric = a
		res = append(res, s)
	}

	return res
}

var (
	testpool = AlertRuleTestPool{pool: make(map[string]*AlertRuleTest)}
)

//AlertRuleTest encapsulates the basic information for testing an alert rule.
type AlertRuleTest struct {
	//Alert rule name
	AlertName string `json:"alert_name"`

	//When this alert rule test will be dropped
	//expirationTime time.Time `yaml:"expiration_time"`

	//The expression used to query metrics used to generate fake alerts.
	TestExpr string `json:"test_expr"`

	//Orignal labels from unmarshaling
	LabelSets []map[string]string `json:"label_sets"`

	//Only the metrics which match the given instances, that is to match the given label set, will be used to generate fake alerts.
	instances []labels.Labels
}

func NewAlertRuleTest(data []byte) (*AlertRuleTest, error) {

	atr := new(AlertRuleTest)
	err := json.Unmarshal(data, atr)
	if err != nil {
		return nil, err
	}

	for _, m := range atr.LabelSets {
		inst := labels.FromMap(m)
		atr.instances = append(atr.instances, inst)
	}

	return atr, nil
}

func (r *AlertRuleTest) Match(lbs labels.Labels) bool {
	nlbs := labels.NewBuilder(lbs).Del(labels.MetricName).Labels()

	for _, inst := range r.instances {
		if labels.Equal(inst, nlbs) {
			return true
		}
	}
	return false
}

type AlertRuleTestPool struct {
	pool   map[string]*AlertRuleTest
	rwLock sync.RWMutex
}

// func init() {

// str := `
// {
//    "alert_name" : "too_many_goroutines",
//    "test_expr" : "(go_goroutines{instance=\"localhost:9090\",job=\"prometheus\"}) > 30",
//    "label_sets": [
//       {
// 		"instance": "localhost:9090",
// 		"job": "prometheus"
// 	  }
//    ]
// }
// `

// AddAlertTestRule([]byte(str))
//
// }

func (p *AlertRuleTestPool) Refresh(tests []*AlertRuleTest) {
	p.rwLock.Lock()
	defer p.rwLock.Unlock()

	m := make(map[string]*AlertRuleTest)

	for _, t := range tests {
		m[t.AlertName] = t
	}
	p.pool = m
}

func (p *AlertRuleTestPool) Get(alertName string) (*AlertRuleTest, bool) {
	p.rwLock.RLock()
	defer p.rwLock.RUnlock()

	t, ok := p.pool[alertName]

	return t, ok
}

//AddAlertTestRule unmarshals the byte stream into AlertRuleTest object and put it into the test pool.
func AddAlertTestRule(data []byte) error {

	atr, err := NewAlertRuleTest(data)
	if err != nil {
		return err
	}

	return testpool.Put(atr)
}

// func (p *AlertRuleTestPool) GetAll() []*AlertRuleTest {
// 	p.rwLock.RLock()
// 	defer p.rwLock.RUnlock()

// 	all := make([]*AlertRuleTest, 0)

// 	for _, v := range p.pool {
// 		all = append(all, v)
// 	}
// 	return all
// }
func (p *AlertRuleTestPool) Put(t *AlertRuleTest) error {

	if t == nil || t.AlertName == "" {
		return errors.New("t is nil or alert name is empty!")
	}

	p.rwLock.Lock()
	defer p.rwLock.Unlock()

	p.pool[t.AlertName] = t

	return nil
}

// func (p *AlertRuleTestPool) Del(alertName string) {
// 	if alertName == "" {
// 		return
// 	}

// 	p.rwLock.Lock()
// 	defer p.rwLock.Unlock()

// 	delete(p.pool, alertName)
// }
