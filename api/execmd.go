package handler

import (
	"fmt"
	"net/http"
	"os/exec"
)

func Execmd(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("bash", "-c", "uname -r")
	whoami, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "执行uname -r 指令结果为：")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "lsb_release -a")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "执行lsb_release -a 指令结果为：")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "free -h")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "执行free -h 指令结果为：")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "df -Th")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "执行df -Th 指令结果为：")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "cat /proc/cpuinfo")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "执行cat /proc/cpuinfo 指令结果为：")
	fmt.Fprintf(w, string(whoami))

	cmd = exec.Command("bash", "-c", "netstat -atunp")
	whoami, _ = cmd.CombinedOutput()
	fmt.Fprintf(w, "执行netstat -atunp 指令结果为：")
	fmt.Fprintf(w, string(whoami))

}
