package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// TimeFunc provides the current time when parsing token to validate "exp" claim (expiration time).
// You can override it to use another time value.  This is useful for testing or if your
// server uses a different time zone than your tokens.
// 变量 TimeFunc 为分析token的claim中exp提供了当前时间,你可以覆盖它使用其他的时间值。
// 如果你的服务器与你的token使用不同的时区，这是非常有用的用来测试
var TimeFunc = time.Now

// Parse methods use this callback function to supply
// the key for verification.  The function receives the parsed,
// but unverified Token.  This allows you to use properties in the
// Header of the token (such as `kid`) to identify which key to use.
// 方法Parse使用这个回调函数提供验证的key值。函数接受带解析没有验证的token.该函数允许使用
// token头信息的中标识的信息确定使用哪个key进行验证
type Keyfunc func(*Token) (interface{}, error)

// A JWT Token.  Different fields will be used depending on whether you're
// creating or parsing/verifying a token.
type Token struct {
	Raw       string                 // The raw token.  Populated when you Parse a token 客户端传送的原始token  解析token时产生
	Method    SigningMethod          // The signing method used or to be used  签名算法
	Header    map[string]interface{} // The first segment of the token  token的头
	Claims    Claims                 // The second segment of the token token的载荷 接口类型
	Signature string                 // The third segment of the token.  Populated when you Parse a token token的签名
	Valid     bool                   // Is the token valid?  Populated when you Parse/Verify a token token是否有效,解析和验证是赋值
}

// Create a new Token.  Takes a signing method  实例化token，设置签名使用的算法
// Claims是一个只包含Valid方法的接口
// MapClaims 实现了Valid方法，所以可以赋值给Claims
func New(method SigningMethod) *Token {
	return NewWithClaims(method, MapClaims{})
}

// 使用签名算法和Claims实例化jwt对象
func NewWithClaims(method SigningMethod, claims Claims) *Token {
	return &Token{
		Header: map[string]interface{}{
			"typ": "JWT", // 这个类型是固定的
			"alg": method.Alg(), // 签名的算法
		},
		Claims: claims, // 数据载荷
		Method: method, // 签名的方法
	}
}

// Get the complete, signed token
// 调用SigningString生成token，签名的过程需要接受签名key
func (t *Token) SignedString(key interface{}) (string, error) {
	var sig, sstr string
	var err error
	// 生成待签名的字符串
	if sstr, err = t.SigningString(); err != nil {
		return "", err
	}
	// 签名操作
	if sig, err = t.Method.Sign(sstr, key); err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

// Generate the signing string.  This is the
// most expensive part of the whole deal.  Unless you
// need this for something special, just go straight for
// the SignedString.
// 生成签名字符串。这是所有处理中最重要的部分。除非你需要一些特殊的操作，否则仅仅使用SignedString进行签名操作
func (t *Token) SigningString() (string, error) {
	var err error
	parts := make([]string, 2)
	for i, _ := range parts {
		var jsonValue []byte
		if i == 0 {
			// 拼装头Header信息，转成json字符串
			if jsonValue, err = json.Marshal(t.Header); err != nil {
				return "", err
			}
		} else {
			 // 拼装 Payload 载荷信息，转成json字符串
			if jsonValue, err = json.Marshal(t.Claims); err != nil {
				return "", err
			}
		}

		parts[i] = EncodeSegment(jsonValue)
	}
	return strings.Join(parts, "."), nil // 使用"."拼接字符串
}

// Parse, validate, and return a token. 解析并且验证token
// keyFunc will receive the parsed token and should return the key for validating.
// keyFunc 应该接收待解析的token并且返回验证使用的key
// If everything is kosher, err will be nil
// 如果验证合法，err将返回nil
func Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return new(Parser).Parse(tokenString, keyFunc)
}

func ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error) {
	return new(Parser).ParseWithClaims(tokenString, claims, keyFunc)
}

// Encode JWT specific base64url encoding with padding stripped
// 使用base64url 编码 JWT
func EncodeSegment(seg []byte) string {
	// TrimRight去除尾部的等号
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
