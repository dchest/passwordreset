package passwordreset

import (
	"testing"
	"os"
)

var (
	testLogin      = "test user"
	testPwdVar     = []byte("test password value")
	testSecret     = []byte("secret key")
	testLoginError = os.NewError("test error")
)

func getPwdVal(login string) ([]byte, os.Error) {
	if login == testLogin {
		return testPwdVar, nil
	}
	return testPwdVar, testLoginError
	//     ^ return it anyway to test that it's not begin used
}

func TestNew(t *testing.T) {
	pwdVal, _ := getPwdVal(testLogin)
	token := NewToken(testLogin, 100, pwdVal, testSecret)
	login, err := VerifyToken(token, getPwdVal, testSecret)
	if err != nil {
		t.Errorf("unexpected error %q", err)
	}
	if login != testLogin {
		t.Errorf("login: expected %q, got %q", testLogin, login)
	}
}

func TestVerify(t *testing.T) {
	bad := []string{
		"",
		"bad token",
		"Talo3mRjaGVzdITUAGOXYZwCMq7EtHfYH4ILcBgKaoWXDHTJOIlBUfcr",
	}
	for i, token := range bad {
		login, err := VerifyToken(token, getPwdVal, testSecret)
		if login != "" {
			t.Errorf(`%d: login for bad token: expected "", got %q`, i, login)
		}
		if err == nil {
			t.Errorf("%d: expected error")
		}
	}
	// Test expiration
	pwdVal, _ := getPwdVal(testLogin)
	token := NewToken(testLogin, -1, pwdVal, testSecret)
	if _, err := VerifyToken(token, getPwdVal, testSecret); err == nil {
		t.Errorf("verified expired token")
	}
	// Test wrong password value
	pwdVal = []byte("wrong value")
	token = NewToken(testLogin, -1, pwdVal, testSecret)
	if _, err := VerifyToken(token, getPwdVal, testSecret); err == nil {
		t.Errorf("verified with wrong password value")
	}
}
