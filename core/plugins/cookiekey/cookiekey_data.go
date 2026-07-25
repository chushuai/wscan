/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package cookiekey

// CommonWeakKeys is a list of commonly used weak secret keys across frameworks.
var CommonWeakKeys = []string{
	"secret",
	"password",
	"changeme",
	"keyboard cat",
	"development",
	"testing",
	"default",
	"supersecret",
	"mysecret",
	"app_secret",
	"secret_key",
	"secret_key_base",
	"your-secret",
	"notsecret",
	"test",
	"abc123",
	"123456",
	"qwerty",
	"changethis",
	"change_me",
	"please_change_me",
	"this_is_not_safe",
	"insecure_secret",
	"example",
	"sample",
	"demo",
	"todo",
	"fixme",
	"replace_me",
	"placeholder",
	"temp",
	"tmp",
	"none",
	"null",
	"undefined",
	"empty",
	"admin",
	"root",
	"master",
	"key",
	"token",
	"s3cr3t",
	"p@ssw0rd",
	"letmein",
	"welcome",
	"monkey",
	"dragon",
	"mustang",
	"iloveyou",
	"trustno1",
	"sunshine",
	"princess",
	"football",
	"shadow",
	"supersecretkey",
	"my_secret_key",
	"app_key",
	"application_secret",
	"s3cret",
	"s3cr3t_k3y",
	"very_secret",
	"so_secret",
	"really_secret",
	"such_secret",
	"much_secret",
	"wow_secret",
}

// DjangoWeakKeys contains Django-specific default/weak SECRET_KEY values.
var DjangoWeakKeys = []string{
	"django-insecure-",
	"django-insecure-^&vc1g%yxbmbg3fs7e0(r1t3xg1m0c#x#mb2&1b3*b$zqfg&n0",
	"django-insecure-7k2t!#v1de$bg8c=zo_p1vm_nx7s%l#a^1u8-bqjw6&3=q^7v5",
	"django-insecure-0b9#m%3gk1dl&w@*q8c^f@-b8o6m5c=e+j3y!t7b$w1d+n%u4",
	"django-insecure-7v&c1e+xg#mmbg3fs7e0(r1t3xg1m0c#x#mb2&1b3*b$zqfg&n0",
	"django-insecure-r#&vc1g%yxbmbg3fs7e0(r1t3xg1m0c#x#mb2&1b3*b$zqfg&n0",
	"example-key-please-change",
	"please-change-me",
	"change-me-in-production",
	"your-secret-key",
	"my-secret-key",
	"sk-1234567890abcdef",
}

// FlaskWeakKeys contains Flask-specific default/weak SECRET_KEY values.
var FlaskWeakKeys = []string{
	"development",
	"production",
	"flask",
	"app",
	"config",
	"key",
	"secret-key",
	"flask-secret",
	"flask_secret_key",
	"flaskapp",
	"myflaskapp",
	"app123",
	"wtf",
	"csrf",
	"session",
	"flasky",
}

// ExpressWeakKeys contains Express cookie-session/express-session weak keys.
var ExpressWeakKeys = []string{
	"keyboard cat",
	"secret",
	"changeme",
	"session secret",
	"session_secret",
	"express",
	"cookie secret",
	"cookie_secret",
	"my secret",
	"my_secret",
	"super secret",
	"super_secret",
	"ssshhh",
	"ssh",
	"hush",
}

// RackWeakKeys contains Ruby/Rack/Rails-specific weak secret_key_base values.
var RackWeakKeys = []string{
	"development_secret_key_base",
	"test_secret_key_base",
	"production_secret_key_base",
	"secret_key_base",
	"0developmentsecret0developmentsecret0developmentse",
	"0testsecret0testsecret0testsecret0testsecret0testsec",
	"f3e2d1c0b9a897867565437382910abcedf0123456789abcdeffedcba98765432",
	"development",
	"test",
	"production",
	"staging",
}

// JWTWeakKeys contains commonly used weak keys for JWT HS256/HS384/HS512 signing.
var JWTWeakKeys = []string{
	"secret",
	"password",
	"key",
	"token",
	"jwt",
	"jwt_secret",
	"your-256-bit-secret",
	"your-384-bit-secret",
	"your-512-bit-secret",
	"super_secret_key",
	"my_secret_key",
	"ssh",
	"0",
	"1",
	"true",
	"false",
	"null",
	"undefined",
	"none",
}

// TornadoWeakKeys contains Tornado-specific default/weak cookie_secret values.
var TornadoWeakKeys = []string{
	"__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
	"32oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
	"secret_cookie",
	"12oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
	"43osdETzKXasdQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
	"TecloigJink4",
	"3%$334ma?asdf2987^%23&^%$2",
	"bZJc2sWbQLKos6GkHn/VB9oXwQt8S0R0kRvJ5/xJ89E=",
	"cookie_secret_code",
	"11oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
	"cookie_secret",
	"61oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
	"43oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
	"adb528da-20bb-4386-8eaf-09f041b569e0",
	"0123456789",
}

// Web2pyWeakKeys contains Web2py-specific default/weak hmac_key values.
var Web2pyWeakKeys = []string{
	"yoursecret",
	"web2py",
	"web2py_secret",
	"application_secret",
	"51e61433a529bf4e",
	"7e03e657-cd42-4341-8bc1-6e31ef6843ea",
}

// Yii2WeakKeys contains Yii2-specific default/weak cookieValidationKey values.
var Yii2WeakKeys = []string{
	"yii2",
	"yii",
	"QmpUmeh62ObG-cBhEXEGksktDXPBD8rW",
	"installer",
	"INSTALLER_COOKIE",
	"cookieValidationKey",
	"<generated_key>",
	"xxxxxxx",
	"setyourkey",
	"testingapp",
	"thisIsAKey",
	"testme",
	"your-validation-key",
	"testValidationKey",
	"xyctuyvibonp",
	"njandsfkasbf",
	"[RANDOM KEY HERE]",
	"[DIFFERENT UNIQUE KEY]",
	"jshd3qjaxp",
	"openep-php",
	"wefJDF8sfdsfSDefwqdxj9oq",
	"7fdsf%dbYd&djsb#sn0mlsfo(kj^kf98dfh",
	"sdi8s#fnj98jwiqiw;qfh!fjgh0d8f",
	"JDqkJaMgIITAKcsJY6yvLQdM9jf7WghX",
	"NAbp2lxwNs8XQ5sbdd46_fzuQdlP6DPy",
	"h8znJTH9JcyYHp7hzP5qiworjFiVtOZx",
	"yYy4YYYX8lYyYyQOl8vOcO6ROo7i8twO",
	"mI3d3FeID5Er9TQVKnjnqOF1j_mJ7HCA",
	"ymoaYrebZHa8gURuolioHGlK8fLXCKjO",
	"wUZvVVKJyHFGDB9qK_Lop4QE1vwb4bYU",
	"<secret random string goes here>",
	"SeCrEt_DeV_Key--DO-NOT-USE-IN-PRODUCTION!",
	"BlGuNEQ7yUWvIKIgJ5NsBSj2TYEzdzRA",
	"-54_EHuCJHZLaTiOyy3owc3BqcayyBes",
}

// LaravelWeakKeys contains Laravel-specific default/weak APP_KEY values.
// Laravel APP_KEY format: "base64:<key>" in .env files.
var LaravelWeakKeys = []string{
	"base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	"base64:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
	"SomeRandomStringSomeRandomString",
	"SomeRandomString",
	"base64:dGVzdGluZ2FwcGtleQ==",
	"base64:aW5zZWN1cmVfa2V5X2Zvcl9kZW1v",
	"change_me",
	"your_app_key",
	"laravel",
	"laravel_secret",
	"base64:SW5zZWN1cmUgS2V5IEZvciBMYXJhdmVs",
}

// BeakerWeakKeys contains Beaker-specific default/weak session.key values.
var BeakerWeakKeys = []string{
	"beaker.session.id",
	"beaker",
	"beaker_secret",
	"session_secret",
	"some_secret",
	"my_session_key",
}

// BottlePyWeakKeys contains BottlePy-specific default/weak secret_key values.
var BottlePyWeakKeys = []string{
	"some-secret-key",
	"somesecretkey",
	"bottle",
	"bottle_secret",
	"the_secret_key",
}

// PyramidWeakKeys contains Pyramid-specific default/weak cookie_secret values.
var PyramidWeakKeys = []string{
	"pyramid",
	"pyramid_secret",
	"cookie_secret",
	"my_cookie_secret",
	"change_me_in_production",
	"TODO_change_me",
}

// AllKeys combines all weak key lists into one deduplicated list.
func AllKeys() []string {
	seen := make(map[string]struct{})
	var result []string
	addKeys := func(keys []string) {
		for _, k := range keys {
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				result = append(result, k)
			}
		}
	}
	addKeys(CommonWeakKeys)
	addKeys(DjangoWeakKeys)
	addKeys(FlaskWeakKeys)
	addKeys(ExpressWeakKeys)
	addKeys(RackWeakKeys)
	addKeys(JWTWeakKeys)
	addKeys(TornadoWeakKeys)
	addKeys(Web2pyWeakKeys)
	addKeys(Yii2WeakKeys)
	addKeys(LaravelWeakKeys)
	addKeys(BeakerWeakKeys)
	addKeys(BottlePyWeakKeys)
	addKeys(PyramidWeakKeys)
	return result
}
