

```azure

name: "custom-sqli"


set:
  r1: randomInt(800000000, 1000000000)

payload:
  - extractvalue(1,concat(char(126),md5({{r1}})))
  
placeholder:
  - query
  - body
  - header
  - cookie

expression:  response.body.bcontains(bytes(substr(md5(string(r1)), 0, 31)))



detail:
  author: shaochuyu
  links:
    - https://github.com/chushuai/wscan
  version: 1.0

```