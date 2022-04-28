package handler

import (
	"fmt"
	"net/http"
	"os/exec"
)

func Execmd(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("bash", "-c", "uname -")
	whoami, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "uname -a  ")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "lsb_release -a")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "lsb_release -a ")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "free -h")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "free -h ")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "df -Th")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "df -Th ")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "cat /proc/cpuinfo")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "cat /proc/cpuinfo ")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "netstat -atunp")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "netstat -atunp ")
	fmt.Fprintf(w, string(whoami))

}
