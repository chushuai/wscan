/**
2 * @Author: shaochuyu
3 * @Date: 12/31/23
4 */

package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
)

// Person 结构体定义
type Person struct {
	Name     string `yaml:"name,omitempty" comment:"Person's name"`
	Age      int    `yaml:"age,omitempty" comment:"Person's age"`
	Location string `yaml:"location,omitempty" comment:"Person's location"`
}

func main() {
	// 创建一个 Person 实例
	person := Person{
		Name:     "John",
		Age:      30,
		Location: "New York",
	}

	// 将 Person 实例序列化为 YAML 格式
	yamlData, err := yaml.Marshal(&person)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// 打印 YAML 数据
	fmt.Println(string(yamlData))
}
