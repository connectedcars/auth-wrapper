package ssh

import (
	"testing"
)

var privateKeyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8A6FGHDiWCSREAXCq6yBfNVr0xCVG2CzvktFNRpue+RXrGs/2
a6ySEJQb3IYquw7HlJgu6fg3WIWhOmHCjfpG0PrL4CRwbqQ2LaPPXhJErWYejcD8
Di00cF3677+G10KMZk9RXbmHtuBFZT98wxg8j+ZsBMqGM1+7yrWUvynswQIDAQAB
AoGAJMCk5vqfSRzyXOTXLGIYCuR4Kj6pdsbNSeuuRGfYBeR1F2c/XdFAg7D/8s5R
38p/Ih52/Ty5S8BfJtwtvgVY9ecf/JlU/rl/QzhG8/8KC0NG7KsyXklbQ7gJT8UT
Ojmw5QpMk+rKv17ipDVkQQmPaj+gJXYNAHqImke5mm/K/h0CQQDciPmviQ+DOhOq
2ZBqUfH8oXHgFmp7/6pXw80DpMIxgV3CwkxxIVx6a8lVH9bT/AFySJ6vXq4zTuV9
6QmZcZzDAkEA2j/UXJPIs1fQ8z/6sONOkU/BjtoePFIWJlRxdN35cZjXnBraX5UR
fFHkePv4YwqmXNqrBOvSu+w2WdSDci+IKwJAcsPRc/jWmsrJW1q3Ha0hSf/WG/Bu
X7MPuXaKpP/DkzGoUmb8ks7yqj6XWnYkPNLjCc8izU5vRwIiyWBRf4mxMwJBAILa
NDvRS0rjwt6lJGv7zPZoqDc65VfrK2aNyHx2PgFyzwrEOtuF57bu7pnvEIxpLTeM
z26i6XVMeYXAWZMTloMCQBbpGgEERQpeUknLBqUHhg/wXF6+lFA+vEGnkY+Dwab2
KCXFGd+SQ5GdUcEMe9isUH6DYj/6/yCDoFrXXmpQb+M=
-----END RSA PRIVATE KEY-----
`)

func TestSshAgent(t *testing.T) {
	//privateKeyBytes, err := ioutil.ReadFile("/home/user/.ssh/id_rsa")
	//if err != nil {
	//	t.Fatal(err)
	//}

	/* sshAuthSock, err := setupAgent(privateKeyBytes, "Qwerty1234")
	if err != nil {
		t.Error(err)
	}

	// Setup exec command
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", []string{"-v", "git@github.com"}...)
	//cmd := exec.CommandContext(ctx, "ssh-add", []string{"-l"}...)
	cmd.Env = []string{"SSH_AUTH_SOCK=" + sshAuthSock}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		t.Error(err)
	}

	err = cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		t.Error("timed out")
	}
	if err != nil {
		t.Error(err)
	} */

}
