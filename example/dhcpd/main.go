package main

import (
	"flag"
	"log"

	"github.com/yudaiyan/go-dhcpd/dhcpd"
)

func main() {
	var ifname string
	flag.StringVar(&ifname, "ifname", "tap-dPeTE", "接口名")
	if err := dhcpd.CreateServer(ifname); err != nil {
		log.Fatalf(err.Error())
	}
}
