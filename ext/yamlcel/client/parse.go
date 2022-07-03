package client

import (
	"bytes"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/parser"
	"github.com/kataras/golog"
	"github.com/thoas/go-funk"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type YamlPoc struct {
	Name      string               `yaml:"name"`
	ID        string               `yaml:"id"`
	Tags      []string             `yaml:"tags"`
	ApplyTo   string               `yaml:"apply_to"`
	Transport string               `yaml:"transport"`
	Set       yaml.Node            `yaml:"set"`
	Rules     map[string]*YamlRule `yaml:"rules"`
	Pattern   string               `yaml:"expression"`
}

type YamlRule struct {
	Name    string `yaml:"-"`
	Request struct {
		Method          string            `yaml:"method"`
		Path            string            `yaml:"path"`
		Headers         map[string]string `yaml:"headers"`
		Body            string            `yaml:"body"`
		FollowRedirects *bool             `yaml:"follow_redirects"`
	} `yaml:"request"`
	Expression string    `yaml:"expression"`
	Output     yaml.Node `yaml:"output"`
}

type MutationRule struct {
	Name        string // eg: poc-yaml-yapi-rce
	Method      string
	ReplacedURI string
	URI         *regexp.Regexp
	Body        *regexp.Regexp
	Header      map[string]*regexp.Regexp

	Status      int
	MutateFuncs []func(resp http.ResponseWriter, ctx *celContext) error

	ExprInfo *expr.SourceInfo
	YamlRule *YamlRule

	Chain *MutationChain
	cel   *celContext
	level int
}

func NewMutationRule(celCtx *celContext) *MutationRule {
	return &MutationRule{
		cel: celCtx,
	}
}

func (m *MutationRule) String() string {
	return m.Chain.Name + "-" + m.Name
}

func (m *MutationRule) Match(req *http.Request, celCtx *celContext) error {
	// extract vars from path
	sortedURL := SortedURI(req.URL)
	for k, v := range m.reSubMatchMap(m.URI, sortedURL, celCtx) {
		celCtx.eval[k] = v
	}
	// extract vars from header
	if len(m.Header) != 0 {
		for k, re := range m.Header {
			value := req.Header.Get(k)
			for k, v := range m.reSubMatchMap(re, value, celCtx) {
				celCtx.eval[k] = v
			}
		}
	}
	// extract vars from body
	if req.Method != http.MethodGet && m.Body != nil {
		body, err := readClose(req.Body)
		if err != nil {
			return err
		}
		for k, v := range m.reSubMatchMap(m.Body, string(body), celCtx) {
			celCtx.eval[k] = v
		}
	}
	return nil
}
func (m *MutationRule) reSubMatchMap(r *regexp.Regexp, str string, celCtx *celContext) map[string]interface{} {
	match := r.FindStringSubmatch(str)
	subMatchMap := make(map[string]string)
	for i, name := range r.SubexpNames() {
		if i != 0 {
			if len(match) <= i {
				fmt.Println(match)
				fmt.Println(r.SubexpNames())
				panic("bug found")
			}
			subMatchMap[name] = match[i]
		}
	}
	// adjust type according to cel context

	result := make(map[string]interface{})
	for k, v := range subMatchMap {
		valueType, ok := celCtx.vafDefines[k]
		if !ok {
			result[k] = v
			continue
		}
		switch valueType.GetPrimitive() {
		case expr.Type_PRIMITIVE_TYPE_UNSPECIFIED, expr.Type_STRING:
			result[k] = v
		case expr.Type_BYTES:
			result[k] = []byte(v)
		case expr.Type_INT64, expr.Type_UINT64:
			num, err := strconv.Atoi(v)
			if err != nil {
				result[k] = v
			} else {
				result[k] = num
			}
		default:
			result[k] = v
		}
	}

	return result
}

func (m *MutationRule) HTTPHandler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		err := m.Match(request, m.cel)
		if err != nil {
			handleError(err, writer)
			return
		}
		for _, fn := range m.MutateFuncs {
			err = fn(writer, m.cel)
			if err != nil {
				golog.Error(err)
			}
		}
		if m.Status != 0 {
			writer.WriteHeader(m.Status)
		}
	}
}

type celContext struct {
	option     []cel.EnvOption
	eval       map[string]interface{}
	vafDefines map[string]*expr.Type
}

func newCelContext() *celContext {
	return &celContext{
		option:     nil,
		eval:       make(map[string]interface{}),
		vafDefines: make(map[string]*expr.Type),
	}
}

type MutationChain struct {
	sync.Mutex
	Name         string
	pattern      []string
	rules        []*MutationRule
	currentLevel int32
	lock         chan struct{}
}

func (g *MutationChain) IsLast(rule *MutationRule) bool {
	return rule.level == len(g.rules)-1
}

func (g *MutationChain) IsFirst(rule *MutationRule) bool {
	return rule.level == 0
}

//func (g *MutationChain) IsNextRun(uri string, rule *MutationRule) bool {
//	subData := rule.reSubMatchMap(rule.URI, uri, rule.cel)
//	for k, v := range subData {
//		existValue := rule.cel.eval[k]
//		if existValue != nil && existValue != v {
//			return false
//		}
//	}
//	return true
//}

type Yarx struct {
	mu     sync.RWMutex
	chains []*MutationChain
}

func (y *Yarx) ParseFile(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return y.Parse(data)
}
func (y *Yarx) Parse(pocData []byte) error {
	var poc YamlPoc
	if bytes.Contains(pocData, []byte("newReverse")) {
		return ErrReverseNotSupported
	}

	err := yaml.Unmarshal(pocData, &poc)
	if err != nil {
		return err
	}

	chain := &MutationChain{
		currentLevel: -1,
		Name:         poc.Name,
		lock:         make(chan struct{}, 1),
	}

	// parse global vars
	env := NewCELEnv()
	varDefines := make(map[string]*expr.Type)
	for i := range poc.Set.Content {
		if i%2 != 0 {
			continue
		}
		key := poc.Set.Content[i].Value
		value := poc.Set.Content[i+1].Value
		ast, issues := env.Compile(value)
		if issues != nil && issues.Err() != nil {
			if strings.Contains(issues.Err().Error(), "undeclared reference to 'request'") {
				return ErrRequestNotSupported
			} else {
				return issues.Err()
			}
		}
		varDefines[key] = ast.ResultType()
	}
	evalMap := make(map[string]interface{})
	executePath, err := y.getShortestPath(&poc)
	golog.Debugf("shortest pattern: %v", executePath)
	chain.pattern = executePath
	for level, ruleName := range executePath {
		rule, ok := poc.Rules[ruleName]
		if !ok {
			return fmt.Errorf("incomplete poc: %s not found", ruleName)
		}
		if err := y.canMock(rule); err != nil {
			return err
		}
		rule.Name = ruleName
		mutateRule := NewMutationRule(&celContext{
			vafDefines: varDefines,
			eval:       evalMap,
		})
		mutateRule.YamlRule = rule
		mutateRule.Chain = chain
		mutateRule.level = level
		mutateRule.Name = ruleName
		mutateRule.cel.vafDefines = varDefines
		if err := y.genRequestMatch(rule, mutateRule); err != nil {
			return fmt.Errorf("generate request matches error: %w", err)
		}
		if err := y.genMutation(rule, mutateRule); err != nil {
			return fmt.Errorf("generate mutation rules error: %w", err)
		}
		varDefines = mutateRule.cel.vafDefines
		chain.rules = append(chain.rules, mutateRule)
	}
	y.mu.Lock()
	defer y.mu.Unlock()
	y.chains = append(y.chains, chain)
	return nil
}

func (y *Yarx) parseExpr(expression string, rule *MutationRule) error {
	pr, _ := parser.NewParser()
	parsed, commonErr := pr.Parse(common.NewTextSource(expression))
	if len(commonErr.GetErrors()) != 0 {
		return fmt.Errorf(commonErr.ToDisplayString())
	}

	rule.ExprInfo = parsed.GetSourceInfo()
	//Rule.ExpectedVars = y.GetInternalIdentifier(parsed.GetExpr())
	return y.walkExpr(parsed.GetExpr(), rule)
}

func (y *Yarx) Chains() []*MutationChain {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return append(y.chains[0:0], y.chains...)
}

func (y *Yarx) Rules() []*MutationRule {
	y.mu.RLock()
	defer y.mu.RUnlock()
	ret := make([]*MutationRule, 0, len(y.chains))
	for _, chain := range y.chains {
		for _, rule := range chain.rules {
			ret = append(ret, rule)
		}
	}
	return ret
}

func (y *Yarx) canMock(yamlRule *YamlRule) error {
	req := yamlRule.Request
	meaningLessKey := []string{"host", "content-length", "content-type"}
	hasBodyOrBody := func() bool {
		if len(yamlRule.Request.Headers) != 0 {
			var gotOtherKey bool
			for k := range yamlRule.Request.Headers {
				if funk.ContainsString(meaningLessKey, strings.ToLower(k)) {
					continue
				}
				gotOtherKey = true
			}
			if gotOtherKey {
				return true
			}
		}
		if yamlRule.Request.Method != http.MethodGet && strings.TrimSpace(yamlRule.Request.Body) != "" {
			return true
		}
		return false
	}()
	if strings.Count(req.Path, "/") < 2 {
		u, err := url.ParseRequestURI(req.Path)
		if err != nil {
			return err
		}
		if strings.Contains(u.RawPath, "{{") && !hasBodyOrBody {
			return fmt.Errorf("path is too flexible to build the route, [%s]", req.Path)
		}
	}
	if (req.Path == "" || req.Path == "/") && !hasBodyOrBody {
		return fmt.Errorf("path is too flexible to build the route, [%s]", req.Path)
	}
	return nil
}

//func (y *Yarx) GetInternalIdentifier(expr *expr.Expr) []string {
//	var result []string
//	result = y.getAllIdentifier(expr, result)
//	result = funk.UniqString(result)
//	var ret []string
//	for _, val := range result {
//		if val == "response" {
//			continue
//		}
//		ret = append(ret, val)
//	}
//	return ret
//}
//
//func (y *Yarx) getAllIdentifier(curExpr *expr.Expr, cur []string) []string {
//	if curExpr.Id == -1 {
//		return cur
//	}
//	switch typedExpr := curExpr.ExprKind.(type) {
//	case *expr.Expr_ConstExpr:
//	case *expr.Expr_IdentExpr:
//		curExpr.Id = -1
//		return append(cur, typedExpr.IdentExpr.Name)
//	case *expr.Expr_SelectExpr:
//		curExpr.Id = -1
//		return y.getAllIdentifier(typedExpr.SelectExpr.GetOperand(), cur)
//	case *expr.Expr_CallExpr:
//		curExpr.Id = -1
//		if typedExpr.CallExpr.Target != nil {
//			cur = append(cur, y.getAllIdentifier(typedExpr.CallExpr.Target, cur)...)
//		}
//		for _, arg := range typedExpr.CallExpr.GetArgs() {
//			cur = append(cur, y.getAllIdentifier(arg, cur)...)
//		}
//	case *expr.Expr_ListExpr:
//	case *expr.Expr_StructExpr:
//	case *expr.Expr_ComprehensionExpr:
//	}
//	return cur
//}

func (y *Yarx) getShortestPath(poc *YamlPoc) ([]string, error) {
	pr, _ := parser.NewParser()
	parsed, commonErr := pr.Parse(common.NewTextSource(poc.Pattern))
	if len(commonErr.GetErrors()) != 0 {
		return nil, fmt.Errorf(commonErr.ToDisplayString())
	}
	return y.getShortestExprPath(parsed.GetExpr(), nil), nil
}

func (y *Yarx) getShortestExprPath(curExpr *expr.Expr, path []string) []string {
	switch curExpr.GetCallExpr().Function {
	case operators.LogicalOr:
		var leftPath, rightPath []string
		args := curExpr.GetCallExpr().GetArgs()
		leftPath = y.getShortestExprPath(args[0], leftPath)
		rightPath = y.getShortestExprPath(args[1], rightPath)
		if len(leftPath) < len(rightPath) {
			path = append(path, leftPath...)
		} else {
			path = append(path, rightPath...)
		}
	case operators.LogicalAnd:
		for _, arg := range curExpr.GetCallExpr().GetArgs() {
			path = y.getShortestExprPath(arg, path)
		}
	default:
		path = append(path, curExpr.GetCallExpr().Function)
	}
	return path
}

func (y *Yarx) genMutation(yamlRule *YamlRule, mutateRule *MutationRule) error {
	if err := y.parseExpr(yamlRule.Expression, mutateRule); err != nil {
		return fmt.Errorf("parsing expression of %s, %s", yamlRule.Name, err)
	}

	if len(yamlRule.Output.Content) != 0 {
		// 这个 Rule 要单独做一些工作，然后合并到主 Rule
		outputRule := NewMutationRule(&celContext{
			eval:       make(map[string]interface{}),
			vafDefines: make(map[string]*expr.Type),
		})
		for i := range yamlRule.Output.Content {
			if i%2 == 0 {
				continue
			}
			value := yamlRule.Output.Content[i].Value
			if err := y.parseExpr(value, outputRule); err != nil {
				return fmt.Errorf("parsing expression of %s, %s", yamlRule.Name, err)
			}
		}
		var metrics RespMetrics
		for _, fn := range outputRule.MutateFuncs {
			if err := fn(&metrics, mutateRule.cel); err != nil {
				return fmt.Errorf("executing output expression of %s, %s", yamlRule.Name, err)
			}
		}
		vars, varTypes, err := executeOutput(yamlRule.Output.Content, &metrics)
		if err != nil {
			return err
		}
		mutateRule.MutateFuncs = append(mutateRule.MutateFuncs, func(resp http.ResponseWriter, ctx *celContext) error {
			for k, v := range metrics.HeaderMap() {
				oldValue := resp.Header().Get(k)
				resp.Header().Set(k, oldValue+v)
			}
			if len(metrics.status) != 0 {
				// 同一个 Rule 内不可能存在 response.status == 200 && response.status == 300
				resp.WriteHeader(metrics.status[0])
			}
			if len(metrics.body) != 0 {
				resp.Write([]byte{'\n'})
				resp.Write(metrics.body)
			}
			return nil
		})
		for k, v := range vars {
			mutateRule.cel.eval[k] = v
		}
		for k, t := range varTypes {
			mutateRule.cel.vafDefines[k] = t
		}
	}
	return nil
}

func (y *Yarx) genRequestMatch(yamlRule *YamlRule, mutateRule *MutationRule) error {
	req := yamlRule.Request
	var uriRegexp, bodyRegexp *regexp.Regexp
	var err error

	// method
	var method = http.MethodGet
	if req.Method != "" {
		method = req.Method
	}
	mutateRule.Method = method

	var replacedStr string
	if req.Path != "" {
		uriInfo, err := url.ParseRequestURI(req.Path)
		if err != nil {
			return err
		}
		uriRegexp, replacedStr, err = variableToRegexp(SortedURI(uriInfo), mutateRule.cel.eval, true, false)
		if err != nil {
			return err
		}
	} else {
		uriRegexp = regexp.MustCompile(``)
	}
	mutateRule.URI = uriRegexp
	mutateRule.ReplacedURI = replacedStr

	// headers
	headerRegexps := make(map[string]*regexp.Regexp)
	for k, v := range req.Headers {
		v = strings.TrimSpace(v)
		var withWrapper = true
		//poc-yaml-confluence-cve-2019-3396-lfi
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
			continue
		}
		// poc-yaml-discuz-wooyun-2010-080723
		if strings.EqualFold(k, "cookie") {
			v = strings.TrimRight(v, ";")
			withWrapper = false
		}
		var headerRe *regexp.Regexp
		if strings.Contains(v, "{{") {
			headerRe, _, err = variableToRegexp(v, mutateRule.cel.eval, withWrapper, false)
		} else {
			headerRe, err = regexp.Compile(regexp.QuoteMeta(v))
		}
		if err != nil {
			return err
		}
		headerRegexps[k] = headerRe
	}
	mutateRule.Header = headerRegexps

	// prepare body
	req.Body = strings.TrimSpace(req.Body)
	if req.Body != "" {
		bodyRegexp, _, err = variableToRegexp(req.Body, mutateRule.cel.eval, false, true)
		if err != nil {
			return err
		}
	} else {
		bodyRegexp = regexp.MustCompile(``)
	}
	mutateRule.Body = bodyRegexp
	return nil
}

func readClose(rc io.ReadCloser) ([]byte, error) {
	defer rc.Close()
	return ioutil.ReadAll(rc)
}

func executeOutput(output []*yaml.Node, resp *RespMetrics) (map[string]interface{}, map[string]*expr.Type, error) {
	result := map[string]interface{}{
		"response.body":    resp.body,
		"response.status":  resp.status,
		"response.headers": resp.HeaderMap(),
	}
	typeMap := make(map[string]*expr.Type)
	env := NewCELEnv()
	for i := range output {
		if i%2 != 0 {
			continue
		}
		var newEnv = env
		key := output[i].Value
		value := output[i+1].Value
		var err error
		for key, t := range typeMap {
			newEnv, err = newEnv.Extend(cel.Declarations(decls.NewVar(key, t)))
			if err != nil {
				return nil, nil, err
			}
		}
		ast, errs := newEnv.Compile(value)
		if errs != nil && errs.Err() != nil {
			return nil, nil, errs.Err()
		}
		typeMap[key] = ast.ResultType()
		prg, err := newEnv.Program(ast)
		if err != nil {
			return nil, nil, err
		}
		out, _, err := prg.Eval(result)
		if err != nil {
			return nil, nil, err
		}
		result[key] = out.Value()
	}
	for k := range result {
		if strings.HasPrefix(k, "response.") {
			delete(result, k)
		}
	}
	return result, typeMap, nil
}

func (y *Yarx) walkExpr(curExpr *expr.Expr, rule *MutationRule) error {
	switch typedExpr := curExpr.ExprKind.(type) {
	case *expr.Expr_ConstExpr:
	case *expr.Expr_IdentExpr:
	case *expr.Expr_SelectExpr:
	case *expr.Expr_CallExpr:
		target := typedExpr.CallExpr.GetTarget()
		if target != nil {
			if err := y.walkExpr(target, rule); err != nil {
				return err
			}
		}
		args := typedExpr.CallExpr.GetArgs()
		function := typedExpr.CallExpr.GetFunction()

		switch function {
		case "bcontains", "contains", "icontains":
			if err := y.onContains(curExpr, rule); err != nil {
				return err
			}
		case "matches", "bmatches":
			if err := y.onMatches(curExpr, rule); err != nil {
				return err
			}
		case "submatch", "bsubmatch":
			if err := y.onSubMatch(curExpr, rule); err != nil {
				return err
			}
		case operators.Equals, operators.NotEquals:
			if err := y.onEqualLike(curExpr, rule); err != nil {
				return err
			}
		default:
		}

		for _, arg := range args {
			if err := y.walkExpr(arg, rule); err != nil {
				return err
			}
		}
	case *expr.Expr_ListExpr:
	case *expr.Expr_StructExpr:
	case *expr.Expr_ComprehensionExpr:
	}
	return nil
}

func (y *Yarx) onEqualLike(curExpr *expr.Expr, rule *MutationRule) error {
	typedExpr := curExpr.ExprKind.(*expr.Expr_CallExpr)
	info := &positionInfo{}
	getCallingPostion(typedExpr, info)
	arg := typedExpr.CallExpr.Args[1]

	// 200 == response.status
	if info.argIndex != 0 {
		arg = typedExpr.CallExpr.Args[0]
	}
	prg, err := y.exprToNewProgram(arg, rule)
	if err != nil {
		return fmt.Errorf("contains function: %w", err)
	}
	switch info.position {
	case PositionBody:
		rule.MutateFuncs = append(rule.MutateFuncs, func(resp http.ResponseWriter, ctx *celContext) error {
			out, _, err := prg.Eval(ctx.eval)
			if err != nil {
				return err
			}
			body := []byte(mustString(out))
			if typedExpr.CallExpr.Function == operators.Equals {
				_, _ = resp.Write(body)
			} else {
				_, _ = resp.Write(append(body, 'k', 'o', 'a', 'l', 'r'))
			}
			return nil
		})
	case PositionStatus:
		statusStr, err := y.exprToString(arg, rule)
		if err != nil {
			return err
		}
		status, err := strconv.Atoi(statusStr)
		if err != nil {
			return err
		}
		if rule.Status != 0 && rule.Status != status {
			golog.Warnf("status may be conflict %d and %d in %s", rule.Status, status, rule.Chain.Name)
		}
		rule.Status = status
		return nil
	case PositionHeader:
		rule.MutateFuncs = append(rule.MutateFuncs, func(resp http.ResponseWriter, ctx *celContext) error {
			out, _, err := prg.Eval(ctx.eval)
			if err != nil {
				return err
			}
			value := mustString(out)
			oldValue := resp.Header().Get(info.headerKey)
			if typedExpr.CallExpr.Function == operators.Equals {
				resp.Header().Set(info.headerKey, oldValue+value)
			} else {
				resp.Header().Set(info.headerKey, oldValue+value+"k")
			}
			return nil
		})
	}
	return nil
}

func (y *Yarx) onMatches(curExpr *expr.Expr, rule *MutationRule) error {
	typedExpr := curExpr.ExprKind.(*expr.Expr_CallExpr)
	info := &positionInfo{}
	getCallingPostion(typedExpr, info)
	prg, err := y.exprToNewProgram(typedExpr.CallExpr.Target, rule)
	if err != nil {
		return fmt.Errorf("contains function: %w", err)
	}
	switch info.position {
	case PositionBody:
		rule.MutateFuncs = append(rule.MutateFuncs, func(resp http.ResponseWriter, ctx *celContext) error {
			out, _, err := prg.Eval(ctx.eval)
			if err != nil {
				return err
			}
			fakeData, err := Generate(mustString(out), 10)
			if err != nil {
				return err
			}
			_, _ = resp.Write([]byte(fakeData))
			return nil
		})
	case PositionHeader:
		rule.MutateFuncs = append(rule.MutateFuncs, func(resp http.ResponseWriter, ctx *celContext) error {
			out, _, err := prg.Eval(ctx.eval)
			if err != nil {
				return err
			}
			fakeData, err := Generate(mustString(out), 10)
			if err != nil {
				return err
			}
			oldValue := resp.Header().Get(info.headerKey)
			resp.Header().Set(info.headerKey, oldValue+fakeData)
			return nil
		})
	default:
		return fmt.Errorf("unknow position in contains function")
	}
	return nil
}

func (y *Yarx) onSubMatch(curExpr *expr.Expr, rule *MutationRule) error {
	typedExpr := curExpr.ExprKind.(*expr.Expr_CallExpr)
	info := &positionInfo{}
	getCallingPostion(typedExpr, info)
	prg, err := y.exprToNewProgram(typedExpr.CallExpr.Target, rule)
	if err != nil {
		return fmt.Errorf("contains function: %w", err)
	}
	switch info.position {
	case PositionBody:
		rule.MutateFuncs = append(rule.MutateFuncs, func(resp http.ResponseWriter, ctx *celContext) error {
			out, _, err := prg.Eval(ctx.eval)
			if err != nil {
				return err
			}
			fakeData, err := Generate(mustString(out), 10)
			if err != nil {
				return err
			}
			_, _ = resp.Write([]byte(fakeData))
			return nil
		})
	case PositionHeader:
		rule.MutateFuncs = append(rule.MutateFuncs, func(resp http.ResponseWriter, ctx *celContext) error {
			out, _, err := prg.Eval(ctx.eval)
			if err != nil {
				return err
			}
			fakeData, err := Generate(mustString(out), 10)
			if err != nil {
				return err
			}
			oldValue := resp.Header().Get(info.headerKey)
			resp.Header().Set(info.headerKey, oldValue+fakeData)
			return nil
		})
	default:
		return fmt.Errorf("unknow position in submatch function")
	}
	return nil
}

func (y *Yarx) onContains(curExpr *expr.Expr, rule *MutationRule) error {
	typedExpr := curExpr.ExprKind.(*expr.Expr_CallExpr)
	info := &positionInfo{}
	getCallingPostion(typedExpr, info)
	prg, err := y.exprToNewProgram(typedExpr.CallExpr.Args[0], rule)
	if err != nil {
		return fmt.Errorf("contains function: %w", err)
	}
	switch info.position {
	case PositionBody:
		rule.MutateFuncs = append(rule.MutateFuncs, func(resp http.ResponseWriter, ctx *celContext) error {
			out, _, err := prg.Eval(ctx.eval)
			if err != nil {
				return err
			}
			_, _ = resp.Write([]byte(mustString(out)))
			return nil
		})
	case PositionHeader:
		rule.MutateFuncs = append(rule.MutateFuncs, func(resp http.ResponseWriter, ctx *celContext) error {
			out, _, err := prg.Eval(ctx.eval)
			if err != nil {
				return err
			}
			oldValue := resp.Header().Get(info.headerKey)
			resp.Header().Set(info.headerKey, oldValue+mustString(out))
			return nil
		})
	default:
		return fmt.Errorf("unknow position in contains function")
	}
	return nil
}

func (y *Yarx) exprToString(pr *expr.Expr, mutateRule *MutationRule) (string, error) {
	ast := cel.ParsedExprToAst(&expr.ParsedExpr{
		Expr:       pr,
		SourceInfo: mutateRule.ExprInfo,
	})
	return cel.AstToString(ast)
}

func (y *Yarx) exprToNewProgram(pr *expr.Expr, mutateRule *MutationRule) (cel.Program, error) {
	ast := cel.ParsedExprToAst(&expr.ParsedExpr{
		Expr:       pr,
		SourceInfo: mutateRule.ExprInfo,
	})
	expression, err := cel.AstToString(ast)
	if err != nil {
		return nil, fmt.Errorf("Rule body: ast to string error:  %w", err)
	}
	//fmt.Printf("partial expr: %s\n", expression)
	env := NewCELEnv()
	var exprDecls []*expr.Decl
	for n, t := range mutateRule.cel.vafDefines {
		exprDecls = append(exprDecls, decls.NewVar(n, t))
	}
	env, err = env.Extend(cel.Declarations(exprDecls...))
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(expression)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	return env.Program(ast)
}

func mustString(val ref.Val) string {
	switch v := val.(type) {
	case types.String:
		return v.Value().(string)
	case types.Bytes:
		return string(v.Value().([]byte))
	case types.Int:
		return fmt.Sprintf("%d", v.Value().(int64))
	default:
		panic("unsupported value type")
	}
}

const (
	PositionBody   = "body"
	PositionHeader = "header"
	PositionStatus = "status"
)

type positionInfo struct {
	position  string
	headerKey string
	argIndex  int
}

func getCallingPostion(curExpr *expr.Expr_CallExpr, info *positionInfo) bool {
	if curExpr.CallExpr.GetTarget() == nil && len(curExpr.CallExpr.GetArgs()) == 2 {
		arg0 := curExpr.CallExpr.Args[0]
		arg1 := curExpr.CallExpr.Args[1]
		switch curExpr.CallExpr.Function {
		case operators.Index:
			if arg0.GetSelectExpr() != nil && arg0.GetSelectExpr().Field == "headers" {
				info.headerKey = arg1.GetConstExpr().GetStringValue()
				info.position = PositionHeader
				return true
			}
		}
	} else {
		switch targetExpr := curExpr.CallExpr.Target.GetExprKind().(type) {
		case *expr.Expr_SelectExpr:
			if getSelectPosition(targetExpr, info) {
				return true
			}
		case *expr.Expr_CallExpr:
			if getCallingPostion(targetExpr, info) {
				return true
			}
		}
	}

	for i, arg := range curExpr.CallExpr.Args {
		switch typedArg := arg.ExprKind.(type) {
		case *expr.Expr_CallExpr:
			if getCallingPostion(typedArg, info) {
				info.argIndex = i
				return true
			}
		case *expr.Expr_SelectExpr:
			if getSelectPosition(typedArg, info) {
				info.argIndex = i
				return true
			}
		}
	}
	return false
}

func getSelectPosition(curExpr *expr.Expr_SelectExpr, info *positionInfo) bool {
	field := curExpr.SelectExpr.Field
	if field == "body" {
		info.position = PositionBody
		return true
	} else if field == "status" {
		info.position = PositionStatus
		return true
	} else if field == "content_type" {
		info.position = PositionHeader
		info.headerKey = "Content-Type"
		return true
	}
	return false
}

type RespMetrics struct {
	body   []byte
	header http.Header
	status []int
}

func (f *RespMetrics) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}
	return f.header
}

func (f *RespMetrics) HeaderMap() map[string]string {
	header := f.Header()
	ret := make(map[string]string)
	for k, vv := range header {
		if len(vv) != 0 {
			ret[k] = vv[0]
		}
	}
	return ret
}

func (f *RespMetrics) Write(bytes []byte) (int, error) {
	f.body = append(f.body, bytes...)
	//f.body = append(f.body, '\n')
	return len(f.body), nil
}

func (f *RespMetrics) WriteHeader(statusCode int) {
	f.status = append(f.status, statusCode)
	return
}
