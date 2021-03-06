package jwt

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// For a type to be a Claims object, it must just have a Valid method that determines
// if the token is invalid for any supported reason
// Claims 的对象，它必须有一个Valid方法用来分析token是否有效
type Claims interface {
	Valid() error
}

// Structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
// See examples for how to use this with your own claim types
// 标准的claims章节，更多参考详情请参考 https://tools.ietf.org/html/rfc7519#section-4.1
type StandardClaims struct {
	Audience  string `json:"aud,omitempty"` // jwt接收者
	ExpiresAt int64  `json:"exp,omitempty"` // jwt的过期时间，这个过期时间必须要大于签发时间
	Id        string `json:"jti,omitempty"` // jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
	IssuedAt  int64  `json:"iat,omitempty"` // 签发时间
	Issuer    string `json:"iss,omitempty"` // 签发人
	NotBefore int64  `json:"nbf,omitempty"` // 定义在什么时间之前，该jwt都是不可用的.
	Subject   string `json:"sub,omitempty"` // jwt所面向的用户
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c StandardClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()  // 将jwt-go提供的时间转换为unix时间戳

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	// 验证是否过期
	if c.VerifyExpiresAt(now, false) == false {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= ValidationErrorExpired
	}

	if c.VerifyIssuedAt(now, false) == false {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if c.VerifyNotBefore(now, false) == false {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

// Compares the aud claim against cmp. 比较aud和cmp
// If required is false, this method will return true if the value matches or is unset
// 如果req是false，在匹配成功和没有设置的情况下该方法将返回true
func (c *StandardClaims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
// 如果req是false，在匹配成功和没有设置的情况下该方法将返回true
func (c *StandardClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	return verifyExp(c.ExpiresAt, cmp, req)
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
// 如果req是false，在匹配成功和没有设置的情况下该方法将返回true
func (c *StandardClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	return verifyIat(c.IssuedAt, cmp, req)
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
// 如果req是false，在匹配成功和没有设置的情况下该方法将返回true
func (c *StandardClaims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
// 如果req是false，在匹配成功和没有设置的情况下该方法将返回true。req为false表示不强求
func (c *StandardClaims) VerifyNotBefore(cmp int64, req bool) bool {
	return verifyNbf(c.NotBefore, cmp, req)
}

// ----- helpers 助手函数

func verifyAud(aud string, cmp string, required bool) bool {
	if aud == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(aud), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}

func verifyIat(iat int64, now int64, required bool) bool {
	if iat == 0 {
		return !required
	}
	return now >= iat
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyNbf(nbf int64, now int64, required bool) bool {
	if nbf == 0 {
		return !required
	}
	return now >= nbf
}
