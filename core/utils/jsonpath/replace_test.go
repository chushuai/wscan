package jsonpath

import (
	"github.com/davecgh/go-spew/spew"
	"sort"
	"strings"
	"testing"
	"wscan/core/utils"
)

type replaceTestCase struct {
	Raw      string
	Expected []string
	Replaced any
}

func TestFindKeys(t *testing.T) {
	for _, c := range []*replaceTestCase{
		{
			Raw: `{"a":1,"b":{"c":"d"}}`,
			Expected: []string{
				"a", "b", "c",
			},
		},
	} {
		result := fetchAllIterKey(c.Raw)
		spew.Dump(result)
	}
}

func TestFindKeys_List(t *testing.T) {
	for _, c := range []*replaceTestCase{
		{
			Raw: `{"a":1,"b":{"c":"d", "e": [{"abc": 123}, {"abc": 333}, {"abc": 666}]}}`,
			Expected: []string{
				"a", "b", "c",
			},
		},
	} {
		result := fetchAllIterKey(c.Raw)
		spew.Dump(result)
	}
}

func TestReplace2(t *testing.T) {
	for _, c := range []*replaceTestCase{
		{
			Raw:      `{"a":1,"b":{"c":"d"}}`,
			Replaced: 23,
			Expected: []string{
				`{"a":23,"b":{"c":"d"}}`,
				`{"a":1,"b":{"c":23}}`,
				`{"a":1,"b":23}`,
			},
		},
		{
			Raw:      `{"a":1,"b":{"c":"d"}}`,
			Replaced: "112",
			Expected: []string{
				`{"a":"112","b":{"c":"d"}}`,
				`{"a":1,"b":{"c":"112"}}`,
				`{"a":1,"b":"112"}`,
			},
		},
	} {
		result := RecursiveDeepReplaceString(c.Raw, c.Replaced)
		if len(result) <= 0 {
			spew.Dump(c)
			spew.Dump(result)
			panic(`RecursiveDeepReplaceString failed`)
		}
		sort.SliceStable(c.Expected, func(i, j int) bool {
			return c.Expected[i] < c.Expected[j]
		})
		sort.SliceStable(result, func(i, j int) bool {
			return result[i] < result[j]
		})
		if len(result) != len(c.Expected) {
			spew.Dump(c)
			spew.Dump(result)
			panic(`RecursiveDeepReplaceString / ExpectLen failed`)
		}

		hash1, hash2 := utils.CalcSha1(strings.Join(c.Expected, "|")), utils.CalcSha1(strings.Join(result, "|"))
		if hash2 != hash1 {
			spew.Dump(c)
			spew.Dump(result)
			panic(`RecursiveDeepReplaceString / Expect Hash failed`)
		}
		spew.Dump(result)
		spew.Dump("h1", hash1, "h2", hash2)
	}
}

func TestReplace3ListRoot(t *testing.T) {
	for _, c := range []*replaceTestCase{
		{
			Raw:      `[{"abc": 123, "ccc": true}]`,
			Replaced: "112",
			Expected: []string{
				`["112"]`,
				`[{"abc":"112","ccc":true}]`,
				`[{"abc":123,"ccc":"112"}]`,
			},
		},
	} {
		result := RecursiveDeepReplaceString(c.Raw, c.Replaced)
		if len(result) <= 0 {
			spew.Dump(c)
			spew.Dump(result)
			panic(`RecursiveDeepReplaceString failed`)
		}
		sort.SliceStable(c.Expected, func(i, j int) bool {
			return c.Expected[i] < c.Expected[j]
		})
		sort.SliceStable(result, func(i, j int) bool {
			return result[i] < result[j]
		})
		if len(result) != len(c.Expected) {
			spew.Dump(c)
			spew.Dump(result)
			panic(`RecursiveDeepReplaceString / ExpectLen failed`)
		}

		hash1, hash2 := utils.CalcSha1(strings.Join(c.Expected, "|")), utils.CalcSha1(strings.Join(result, "|"))
		if hash2 != hash1 {
			spew.Dump(c)
			spew.Dump(result)
			panic(`RecursiveDeepReplaceString / Expect Hash failed`)
		}
		spew.Dump(result)
		spew.Dump("h1", hash1, "h2", hash2)
	}
}

func TestReplace3List(t *testing.T) {
	for _, c := range []*replaceTestCase{
		{
			Raw:      `{"root":[{"abc": 123, "ccc": true}]}`,
			Replaced: "112",
			Expected: []string{
				`{"root":"112"}`,
				`{"root":["112"]}`,
				`{"root":[{"abc":"112","ccc":true}]}`,
				`{"root":[{"abc":123,"ccc":"112"}]}`,
			},
		},
	} {
		result := RecursiveDeepReplaceString(c.Raw, c.Replaced)
		if len(result) <= 0 {
			spew.Dump(c)
			spew.Dump(result)
			panic(`RecursiveDeepReplaceString failed`)
		}
		sort.SliceStable(c.Expected, func(i, j int) bool {
			return c.Expected[i] < c.Expected[j]
		})
		sort.SliceStable(result, func(i, j int) bool {
			return result[i] < result[j]
		})
		if len(result) != len(c.Expected) {
			spew.Dump(c)
			spew.Dump(result)
			panic(`RecursiveDeepReplaceString / ExpectLen failed`)
		}

		hash1, hash2 := utils.CalcSha1(strings.Join(c.Expected, "|")), utils.CalcSha1(strings.Join(result, "|"))
		if hash2 != hash1 {
			spew.Dump(c)
			spew.Dump(result)
			panic(`RecursiveDeepReplaceString / Expect Hash failed`)
		}
		spew.Dump(result)
		spew.Dump("h1", hash1, "h2", hash2)
	}
}
