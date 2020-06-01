package formatter

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/optiopay/klar/clair"
)

const (
	oneMsSecondDuration time.Duration = time.Duration(1) * time.Millisecond
)

// JUnitTestSuites is a collection of JUnit test suites.
type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []JUnitTestSuite `xml:"testsuite"`
	Name    string           `xml:"name,attr"`
}

// JUnitTestSuite is a single JUnit test suite which may contain many
// testcases.
type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Time       string          `xml:"time,attr"`
	Name       string          `xml:"name,attr"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase is a single test case with its result.
type JUnitTestCase struct {
	XMLName     xml.Name          `xml:"testcase"`
	Classname   string            `xml:"classname,attr"`
	Name        string            `xml:"name,attr"`
	Time        string            `xml:"time,attr"`
	SkipMessage *JUnitSkipMessage `xml:"skipped,omitempty"`
	Failure     *JUnitFailure     `xml:"failure,omitempty"`
}

// JUnitSkipMessage contains the reason why a testcase was skipped.
type JUnitSkipMessage struct {
	Message string `xml:"message,attr"`
}

// JUnitProperty represents a key/value pair used to define properties.
type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// JUnitFailure contains data related to a failed test.
type JUnitFailure struct {
	Message  string `xml:"message,attr"`
	Type     string `xml:"type,attr"`
	Contents string `xml:",chardata"`
}

// JUnitReportXML writes a JUnit xml representation of the clair Vulnerabilities
// to a xml file with the file name of the image.
// format described at http://windyroad.org/dl/Open%20Source/JUnit.xsd
func JUnitReportXML(vsMap map[string][]*clair.Vulnerability, imageName string) error {
	suites := JUnitTestSuites{}
	suites.Name = imageName
	// Remove all special chars (expect .) from imageName
	reg, err := regexp.Compile("[^.a-zA-Z0-9]+")
	if err != nil {
		return err
	}
	cleanImageName := reg.ReplaceAllString(imageName, "_")

	// convert vulnerability map to individual test suites
	for sev, vs := range vsMap {
		ts := JUnitTestSuite{
			Tests:    len(vs),
			Failures: len(vs),
			Time:     formatTime(oneMsSecondDuration),
			Name:     cleanImageName + "_" + sev,
			// We could add properties here.
			// Properties: []JUnitProperty{},
			TestCases: []JUnitTestCase{},
		}

		// individual test cases
		for _, vulnerability := range vs {
			testCase := JUnitTestCase{
				Classname: vulnerability.FeatureName,
				Name:      vulnerability.Name + " [" + vulnerability.Severity + "]",
				Time:      formatTime(oneMsSecondDuration),
				Failure: &JUnitFailure{
					Message:  vulnerability.FeatureName + " [" + vulnerability.FeatureVersion + "]: " + vulnerability.Link,
					Type:     "ERROR",
					Contents: vulnerability.Description,
				},
			}
			if vulnerability.FixedBy != "" {
				testCase.Failure.Contents = testCase.Failure.Contents + " FIXED BY: " + vulnerability.FixedBy
			}
			ts.TestCases = append(ts.TestCases, testCase)
		}

		suites.Suites = append(suites.Suites, ts)
	}

	if len(vsMap) == 0 {
		suites.Suites = append(suites.Suites, noVulnerabilitiesFound(cleanImageName))
	}

	// to xml
	bytes, err := xml.MarshalIndent(suites, "", "\t")
	if err != nil {
		return err
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		// TODO
		return err
	}
	f, err := os.Create(filepath.Join(dir, "CLAIR-"+cleanImageName+".xml"))
	if err != nil {
		fmt.Println(err)
		// TODO
		return err
	}
	writer := bufio.NewWriter(f)
	writer.WriteString(xml.Header)
	writer.Write(bytes)
	// writer.WriteByte('\n')
	writer.Flush()

	return nil
}

func formatTime(d time.Duration) string {
	return fmt.Sprintf("%.3f", d.Seconds())
}

func noVulnerabilitiesFound(testSuiteName string) JUnitTestSuite {
	ts := JUnitTestSuite{
		Tests:      1,
		Failures:   0,
		Time:       formatTime(oneMsSecondDuration),
		Name:       testSuiteName,
		Properties: []JUnitProperty{},
		TestCases:  []JUnitTestCase{},
	}
	testCase := JUnitTestCase{
		Classname: "no.vulnerabilities.found",
		Name:      "No vulnerabilities found",
		Time:      formatTime(oneMsSecondDuration),
	}
	ts.TestCases = append(ts.TestCases, testCase)
	return ts
}
