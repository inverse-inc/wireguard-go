package route53

import (
	"testing"

	"github.com/coredns/caddy"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
)

func TestSetupRoute53(t *testing.T) {
	f = func(credential *credentials.Credentials) route53iface.Route53API {
		return fakeRoute53{}
	}

	tests := []struct {
		body          string
		expectedError bool
	}{
		{`route53`, false},
		{`route53 :`, true},
		{`route53 example.org:12345678`, false},
		{`route53 example.org:12345678 {
    aws_access_key
}`, true},
		{`route53 example.org:12345678 { }`, false},

		{`route53 example.org:12345678 { }`, false},
		{`route53 example.org:12345678 { wat
}`, true},
		{`route53 example.org:12345678 {
    aws_access_key ACCESS_KEY_ID SEKRIT_ACCESS_KEY
}`, false},

		{`route53 example.org:12345678 {
    fallthrough
}`, false},
		{`route53 example.org:12345678 {
		credentials
	}`, true},

		{`route53 example.org:12345678 {
		credentials default
	}`, false},
		{`route53 example.org:12345678 {
		credentials default credentials
	}`, false},
		{`route53 example.org:12345678 {
		credentials default credentials extra-arg
	}`, true},
		{`route53 example.org:12345678 example.org:12345678 {
	}`, true},

		{`route53 example.org:12345678 {
	refresh 90
}`, false},
		{`route53 example.org:12345678 {
	refresh 5m
}`, false},
		{`route53 example.org:12345678 {
	refresh
}`, true},
		{`route53 example.org:12345678 {
	refresh foo
}`, true},
		{`route53 example.org:12345678 {
	refresh -1m
}`, true},

		{`route53 example.org {
	}`, true},
	}

	for _, test := range tests {
		c := caddy.NewTestController("dns", test.body)
		if err := setup(c); (err == nil) == test.expectedError {
			t.Errorf("Unexpected errors: %v", err)
		}
	}
}
