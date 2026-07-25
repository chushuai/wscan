package jsonpath

import (
	"github.com/davecgh/go-spew/spew"
	"testing"
)

const (
	raw = `{
    "store": {
        "book": [
            {
                "category": "reference",
                "author": "Nigel Rees",
                "title": "Sayings of the Century",
                "price": 8.95
            },
            {
                "category": "fiction",
                "author": "Evelyn Waugh",
                "title": "Sword of Honour",
                "price": 12.99
            },
            {
                "category": "fiction",
                "author": "Herman Melville",
                "title": "Moby Dick",
                "isbn": "0-553-21311-3",
                "price": 8.99
            },
            {
                "category": "fiction",
                "author": "J. R. R. Tolkien",
                "title": "The Lord of the Rings",
                "isbn": "0-395-19395-8",
                "price": 22.99
            }
        ],
        "bicycle": {
            "color": "red",
            "price": 19.95
        }
    },
    "expensive": 10
}`
)

func TestRead1(t *testing.T) {
	var a = Find(raw, "$..bicycle.color")
	spew.Dump(a)
	var b = FindFirst(raw, "$..bicycle.color")
	spew.Dump(b)
}

func TestReadAll(t *testing.T) {
	var result = Find(raw, `$..*`)
	spew.Dump(result)
}
