package jwt

import (
	"errors"
)

// Error constants
var (
	ErrInvalidKey      = errors.New("key is invalid") // 无效的key
	ErrInvalidKeyType  = errors.New("key is of invalid type") // key是无效的类型
	ErrHashUnavailable = errors.New("the requested hash function is unavailable")
)

// The errors that might occur when parsing and validating a token
// 解析或验证token时可能发生的错误
const (
	ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed 无法理解的token
	ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                    // Signature validation failed

	// Standard Claim validation errors 标准Claim验证错误
	ValidationErrorAudience      // AUD validation failed  Audience验证失败
	ValidationErrorExpired       // EXP validation failed  过期时间验证失败
	ValidationErrorIssuedAt      // IAT validation failed  签发时间验证失败
	ValidationErrorIssuer        // ISS validation failed  签发者验证失败
	ValidationErrorNotValidYet   // NBF validation failed  jwt开始时间验证失败
	ValidationErrorId            // JTI validation failed  签发标识验证失败
	ValidationErrorClaimsInvalid // Generic claims validation error
)

// Helper for constructing a ValidationError with a string error message
func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
	return &ValidationError{
		text:   errorText, // 错误信息
		Errors: errorFlags, // 错误标识
	}
}

// The error from Parse if token is not valid 解析时令牌token无效返回的错误
type ValidationError struct {
	Inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
	Errors uint32 // bitfield.  see ValidationError... constants
	text   string // errors that do not have a valid error just have text 没有错误仅仅包含文本信息
}

// Validation error is an error type
func (e ValidationError) Error() string {
	if e.Inner != nil {
		return e.Inner.Error()
	} else if e.text != "" {
		return e.text
	} else {
		return "token is invalid"
	}
}

// No errors 没有错误
func (e *ValidationError) valid() bool {
	return e.Errors == 0
}
