package handler

import (
	"fmt"
	"net/http"
	"os/exec"
)

func Execmd(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("whoami")
	whoami, _ := cmd.Output()
	fmt.Fprintf(w, string(whoami))

}
