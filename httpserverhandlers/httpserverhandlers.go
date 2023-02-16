package httpserverhandlers

import (
	"fmt"
	"os"
	"os/exec"
)

type HttpServerHandler interface {
	IsRunning() bool
	ReloadConfiguration() error
	ServerName() string
}

func ByName(handlerName string) (HttpServerHandler, error) {
	switch handlerName {
	case "nginx":
		return &Nginx{}, nil
	case "none":
		return &NullServerHandler{}, nil
	default:
		return nil, fmt.Errorf("Unsupported http server handler: '%s'", handlerName)
	}
}

type NullServerHandler struct{}

func (self *NullServerHandler) IsRunning() bool {
	return false
}

func (self *NullServerHandler) ReloadConfiguration() error {
	return nil
}

func (self *NullServerHandler) ServerName() string {
	return "none"
}

type Nginx struct{}

func (self *Nginx) IsRunning() bool {
	return fileExists("/var/run/nginx.pid")
}

func (self *Nginx) ReloadConfiguration() error {
	return exec.Command("nginx", "-s", "reload").Run()
}

func (self *Nginx) ServerName() string {
	return "nginx"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
