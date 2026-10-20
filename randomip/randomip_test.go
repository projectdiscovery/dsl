package randomip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetRandomIp(t *testing.T) {
	tests := []struct {
		name     string
		cidr     []string
		errorMsg string
		valid    bool
	}{
		{
			name:  "Valid C class",
			cidr:  []string{"193.6.32.110/24"},
			valid: true,
		},
		{
			name:  "Valid B class",
			cidr:  []string{"128.34.33.29/16"},
			valid: true,
		},
		{
			name:  "Valid A class",
			cidr:  []string{"10.1.2.3/8"},
			valid: true,
		},
		{
			name:  "Valid classless zero based network",
			cidr:  []string{"205.102.139.2/30"},
			valid: true,
		},
		{
			name:  "Valid classless non-zero based network",
			cidr:  []string{"205.102.139.49/29"},
			valid: true,
		},
		{
			name:  "Multiple CIDRs",
			cidr:  []string{"1.2.3.4/15", "230.149.150.22/28"},
			valid: true,
		},
		{
			name:     "Negativ CIDR length",
			cidr:     []string{"10.11.12.13/-1"},
			valid:    false,
			errorMsg: "10.11.12.13/-1 is not a valid CIDR",
		},
		{
			name:     "Large CIDR length",
			cidr:     []string{"10.11.12.13/33"},
			valid:    false,
			errorMsg: "10.11.12.13/33 is not a valid CIDR",
		},
		{
			name:     "No CIDR provided",
			cidr:     []string{},
			valid:    false,
			errorMsg: "must specify at least one cidr",
		},
		{
			name:  "Valid but crazy",
			cidr:  []string{"0.0.0.0/0"},
			valid: true,
		},
		{
			name:  "Valid but unlikely",
			cidr:  []string{"193.6.32.109/32"},
			valid: true,
		},
		{
			name:  "Valid IPv6",
			cidr:  []string{"2607:fb91:1294:85fa:3cbf:491:cd46:2625/120"},
			valid: true,
		},
		{
			name:  "Classless IPv4 starting with a non-zero base",
			cidr:  []string{"129.47.78.253/30"},
			valid: true,
		},
		{
			name:  "IPv6 and IPv4",
			cidr:  []string{"2603:8080:4400:d070:913:dee4:6c0c:9ae8/96", "212.78.146.240/25"},
			valid: true,
		},
		{
			name:     "Negative CIDR length IPv6",
			cidr:     []string{"2600:1700:27c:70:44eb:2d78:86b3:e905/-1"},
			valid:    false,
			errorMsg: "2600:1700:27c:70:44eb:2d78:86b3:e905/-1 is not a valid CIDR",
		},
		{
			name:     "Large CIDR length IPv6",
			cidr:     []string{"2607:fb91:bd02:127c:d736:abcf:5c77:e7fd/129"},
			valid:    false,
			errorMsg: "2607:fb91:bd02:127c:d736:abcf:5c77:e7fd/129 is not a valid CIDR",
		},
		{
			name:  "Valid but unlikely IPv6",
			cidr:  []string{"2607:fb91:bd02:127c:d736:abcf:5c77:e7fd/128"},
			valid: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip, err := GetRandomIPWithCidr(test.cidr...)
			if test.valid {
				require.NoError(t, err)
				anyInRange := false
				for _, cidr := range test.cidr {
					_, network, _ := net.ParseCIDR(cidr)
					anyInRange = anyInRange || network.Contains(ip)
				}
				require.Truef(t, anyInRange, "the IP address returned %v is not in range of the provided CIDRs", ip)
			} else {
				require.Error(t, err, test.errorMsg)
			}
		})
	}
}

// An invalid cidr used to be reported only when the draw happened to land on
// it, so the same call failed intermittently and the error named a different
// cidr each time.
func TestGetRandomIPWithCidrRejectsInvalidRegardlessOfDraw(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cidrs []string
		want  string
	}{
		{name: "invalid second", cidrs: []string{"10.0.0.0/8", "not-a-cidr"}, want: "not-a-cidr"},
		{name: "invalid first", cidrs: []string{"not-a-cidr", "10.0.0.0/8"}, want: "not-a-cidr"},
		{name: "invalid among many", cidrs: []string{"10.0.0.0/8", "192.168.0.0/16", "nope", "172.16.0.0/12"}, want: "nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Repeated so a draw that avoids the invalid entry cannot pass by luck.
			for i := 0; i < 50; i++ {
				_, err := GetRandomIPWithCidr(tc.cidrs...)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.want)
			}
		})
	}
}

func TestGetRandomIPWithCidrStillDrawsFromAllValid(t *testing.T) {
	seen := map[bool]bool{}
	for i := 0; i < 200; i++ {
		ip, err := GetRandomIPWithCidr("10.0.0.0/8", "192.168.0.0/16")
		require.NoError(t, err)
		seen[ip.String()[:2] == "10"] = true
	}
	require.Len(t, seen, 2, "both cidrs should still be drawn from")
}
