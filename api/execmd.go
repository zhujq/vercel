package handler

import (
	"fmt"
	"net/http"
	"os/exec"
)

func Execmd(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("bash", "-c", "uname -r")
	whoami, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, string(whoami))

}
