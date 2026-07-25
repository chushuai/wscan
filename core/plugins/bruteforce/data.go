/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package bruteforce

import (
	"bufio"
	"embed"
	"wscan/core/utils/log"
)

//go:embed dict
var dictFile embed.FS

func LoadDict(filePath string) (ret []string) {
	file, err := dictFile.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ret = append(ret, scanner.Text())

	}
	return
}

func LoadBuiltinUserPass() (users []string, pass []string) {
	users = LoadDict("dict/username.txt")
	pass = LoadDict("dict/password.txt")
	return
}
