// Copyright 2016 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package martian

import (
	"flag"

	mlog "github.com/google/martian/v3/log"
)

var (
	// level 注册 -v 标志;若已被别的库(如 golang/glog)注册则复用占位 int,
	// 避免 "flag redefined: v" panic。wscan 同时引入 martian 与 glog,两者都
	// 向 flag.CommandLine 注册 "v" 会冲突。
	level = func() *int {
		if f := flag.Lookup("v"); f != nil {
			// 已存在,返回一个零值指针,mlog.SetLevel(0) 即默认级别。
			return new(int)
		}
		return flag.Int("v", 0, "log level")
	}()
)

// Init runs common initialization code for a martian proxy.
func Init() {
	mlog.SetLevel(*level)
}
