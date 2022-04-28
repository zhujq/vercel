package handler

import (
	"fmt"
	"net/http"
	"os/exec"
)

func Execmd(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("bash", "-c", "uname -a")
	whoami, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "uname -a \n ")
	fmt.Fprintf(w, string(whoami))
	fmt.Fprintf(w, "\n")

	cmd := exec.Command("bash", "-c", "ls -al ./")
	whoami, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "ls -al ./ \n ")
	fmt.Fprintf(w, string(whoami))
	fmt.Fprintf(w, "\n")

	cmd = exec.Command("bash", "-c", "lsb_release -a")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "lsb_release -a \n")
	fmt.Fprintf(w, string(whoami))
	fmt.Fprintf(w, "\n")

	cmd = exec.Command("bash", "-c", "free -h")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "free -h \n")
	fmt.Fprintf(w, string(whoami))
	fmt.Fprintf(w, "\n")

	cmd = exec.Command("bash", "-c", "df -Th")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "df -Th \n ")
	fmt.Fprintf(w, string(whoami))
	fmt.Fprintf(w, "\n")

	cmd = exec.Command("bash", "-c", "cat /proc/cpuinfo")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "cat /proc/cpuinfo \n")
	fmt.Fprintf(w, string(whoami))
	fmt.Fprintf(w, "\n")

	cmd = exec.Command("bash", "-c", "netstat -atunp")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "netstat -atunp \n")
	fmt.Fprintf(w, string(whoami))
	fmt.Fprintf(w, "\n")

}
