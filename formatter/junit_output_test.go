package formatter

import (
	"encoding/xml"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/optiopay/klar/clair"
	"github.com/stretchr/testify/assert"
)

const (
	imageName   = "test_image:latest"
	xmlFileName = "CLAIR-test_image_latest.xml"
)

func generateVulnerabilityMap() map[string][]*clair.Vulnerability {
	vsMap := map[string][]*clair.Vulnerability{}
	lowVul := clair.Vulnerability{
		Description:    "descLow",
		FeatureName:    "featureNameLow",
		FeatureVersion: "1.0",
		FixedBy:        "fixedByLow",
		Link:           "http://link.com.low",
		Name:           "nameLow",
		Severity:       "low",
	}
	medVul := clair.Vulnerability{
		Description:    "descMed",
		FeatureName:    "featureNameMed",
		FeatureVersion: "1.0",
		FixedBy:        "fixedByMed",
		Link:           "http://link.com.med",
		Name:           "nameMed",
		Severity:       "med",
	}
	medVul2 := clair.Vulnerability{
		Description:    "descMed2",
		FeatureName:    "featureNameMed2",
		FeatureVersion: "1.0",
		FixedBy:        "fixedByMed2",
		Link:           "http://link.com.med2",
		Name:           "nameMed2",
		Severity:       "med",
	}
	vsMap["low"] = []*clair.Vulnerability{
		&lowVul,
	}
	vsMap["med"] = []*clair.Vulnerability{
		&medVul,
		&medVul2,
	}
	return vsMap
}

func TestJUnitReportXML(t *testing.T) {
	vsMap := generateVulnerabilityMap()

	err := JUnitReportXML(vsMap, imageName)
	assert.Nil(t, err)

	xmlFile, _ := os.Open(xmlFileName)
	defer xmlFile.Close()

	byteValue, _ := ioutil.ReadAll(xmlFile)
	var suites JUnitTestSuites
	xml.Unmarshal(byteValue, &suites)

	assert.EqualValues(t, imageName, suites.Name)
	lowSuit := getSuitBySeverity(suites.Suites, "low")
	medSuit := getSuitBySeverity(suites.Suites, "med")

	assert.EqualValues(t, 1, lowSuit.Tests)
	assert.EqualValues(t, vsMap["low"][0].Name+" [low]", lowSuit.TestCases[0].Name)
	assert.EqualValues(t, 2, medSuit.Tests)
	assert.EqualValues(t, 2, medSuit.Failures)
	assert.EqualValues(t, vsMap["med"][0].Name+" [med]", medSuit.TestCases[0].Name)
	assert.EqualValues(t, vsMap["med"][1].Name+" [med]", medSuit.TestCases[1].Name)

	cleanUp(t)
}

func TestJUnitReportXMLNoVulnerabilities(t *testing.T) {
	vsMap := map[string][]*clair.Vulnerability{}

	err := JUnitReportXML(vsMap, imageName)
	assert.Nil(t, err)
	cleanUp(t)
}

func Test_formatTime(t *testing.T) {
	type args struct {
		d time.Duration
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			args: args{
				d: time.Duration(1) * time.Millisecond,
			},
			want: "0.001",
		},
		{
			args: args{
				d: time.Duration(2) * time.Millisecond,
			},
			want: "0.002",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTime(tt.args.d); got != tt.want {
				t.Errorf("formatTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_noVulnerabilitiesFound(t *testing.T) {
	type args struct {
		testSuiteName string
	}
	tests := []struct {
		name string
		args args
		want JUnitTestSuite
	}{
		{
			args: args{
				testSuiteName: imageName,
			},
			want: JUnitTestSuite{
				Tests:      1,
				Failures:   0,
				Time:       formatTime(oneMsSecondDuration),
				Name:       imageName,
				Properties: []JUnitProperty{},
				TestCases: []JUnitTestCase{
					{
						Classname: "no.vulnerabilities.found",
						Name:      "No vulnerabilities found",
						Time:      formatTime(oneMsSecondDuration),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := noVulnerabilitiesFound(tt.args.testSuiteName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("noVulnerabilitiesFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getSuitBySeverity(suites []JUnitTestSuite, sev string) JUnitTestSuite {
	for _, v := range suites {
		if strings.Contains(v.Name, sev) {
			return v
		}
	}
	return JUnitTestSuite{}
}

// cleanUp created xml mock files
func cleanUp(t *testing.T) {

	t.Cleanup(func() {
		dir, _ := os.Getwd()
		files, _ := filepath.Glob(filepath.Join(dir, "CLAIR-*.xml"))
		for _, f := range files {
			if err := os.Remove(f); err != nil {
				panic(err)
			}
		}
	})

}
