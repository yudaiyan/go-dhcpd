package dhcpd

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/yudaiyan/go-netlink/netlink"
	"github.com/yudaiyan/go-sync/sync"
)

type dhcpd struct {
	// net.HardwareAddr 替换为 [6]byte，才是可比较的
	macs sync.SyncList[[6]byte]
	// 本地网卡名
	ifname string
	// ifname 的 localMask
	localMask net.IPMask
	// ifname 的 localIp
	localIp net.IP
	// ifname 的 localMac
	localMac net.HardwareAddr
	// 作为dhcpd监听的端口
	serverPort int
}

func (s *dhcpd) handler(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	if m == nil {
		log.Printf("packet is nil!")
		return
	}
	if m.OpCode != dhcpv4.OpcodeBootRequest {
		log.Printf("not a BootRequest!")
		return
	}

	switch mt := m.MessageType(); mt {
	case dhcpv4.MessageTypeDiscover:
		payload, err := s.createUnicastPayload(m, dhcpv4.MessageTypeOffer)
		if err != nil {
			log.Printf("cannot create offer: %v", err)
			return
		}
		if s.sendUnicast(peer.(*net.UDPAddr), m, payload) != nil {
			log.Printf("cannot reply to client: %v", err)
			return
		}
	case dhcpv4.MessageTypeRequest:
		if m.RequestedIPAddress() == nil {
			log.Println("requestedIPAddress is nil, drop it")
			return
		}
		if ipToComparator(m.RequestedIPAddress()) == ipToComparator(s.genIP(m.ClientHWAddr)) {
			payload, err := s.createUnicastPayload(m, dhcpv4.MessageTypeAck)
			if err != nil {
				log.Printf("cannot create ack: %v", err)
				return
			}
			if s.sendUnicast(peer.(*net.UDPAddr), m, payload) != nil {
				log.Printf("cannot reply to client: %v", err)
				return
			}
		} else {
			payload, err := s.createBroadcastPayload(m, dhcpv4.MessageTypeNak)
			if err != nil {
				log.Printf("cannot create nak: %v", err)
				return
			}
			if _, err := conn.WriteTo(payload.ToBytes(), peer); err != nil {
				log.Printf("Cannot reply to client: %v", err)
				return
			}
		}

	default:
		log.Printf("unhandled message type: %v", mt)
		return
	}
}

// 根据mac生成ip
func (s *dhcpd) genIP(hardwareAddr net.HardwareAddr) net.IP {
	var mac [6]byte
	copy(mac[:], hardwareAddr)

	var ip3 byte
	if i, ok := s.macs.Find(mac); ok {
		ip3 = byte(i + 2)
	} else {
		ip3 = byte(s.macs.Size() + 2)
		s.macs.Add(mac)
	}
	return net.IP{s.localIp[0], s.localIp[1], s.localIp[2], ip3}
}

// 构建用于单播的eth、ipv4、udp层
func (s *dhcpd) createUnicastLayer(dstIP net.IP, dstMAC net.HardwareAddr, dstPort layers.UDPPort) (*layers.Ethernet, *layers.IPv4, *layers.UDP) {
	// 构建以太网帧
	eth := &layers.Ethernet{
		SrcMAC:       s.localMac, // 源 MAC 地址
		DstMAC:       dstMAC,     // 目标 MAC 地址
		EthernetType: layers.EthernetTypeIPv4,
	}

	// 构建 IP 层
	ipv4 := &layers.IPv4{
		SrcIP:    s.localIp, // 源 IP 地址
		DstIP:    dstIP,     // 目标 IP 地址
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
		Version:  4,
		TTL:      128,
	}

	// 构建 UDP 层
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(s.serverPort),
		DstPort: dstPort,
	}
	udp.SetNetworkLayerForChecksum(ipv4)
	return eth, ipv4, udp
}

// 构建用于单播的负载，表示dhcp成功
func (s *dhcpd) createUnicastPayload(m *dhcpv4.DHCPv4, messageType dhcpv4.MessageType) (*dhcpv4.DHCPv4, error) {
	var reply *dhcpv4.DHCPv4
	reply, err := dhcpv4.NewReplyFromRequest(m)
	if err != nil {
		return nil, err
	}

	reply.UpdateOption(dhcpv4.OptMessageType(messageType))
	reply.UpdateOption(dhcpv4.OptServerIdentifier(s.localIp))
	reply.UpdateOption(dhcpv4.OptIPAddressLeaseTime(time.Hour * 6))
	reply.UpdateOption(dhcpv4.OptSubnetMask(s.localMask))
	reply.UpdateOption(dhcpv4.OptRouter(s.localIp))
	reply.SetUnicast()
	reply.Options.Del(dhcpv4.OptionClientIdentifier)

	reply.YourIPAddr = s.genIP(m.ClientHWAddr)
	reply.ServerIPAddr = s.localIp
	return reply, nil
}

// 构建用于组播的负载，表示dhcp失败
func (s *dhcpd) createBroadcastPayload(m *dhcpv4.DHCPv4, messageType dhcpv4.MessageType) (*dhcpv4.DHCPv4, error) {
	var reply *dhcpv4.DHCPv4
	reply, err := dhcpv4.NewReplyFromRequest(m)
	if err != nil {
		return nil, err
	}
	reply.UpdateOption(dhcpv4.OptMessageType(messageType))
	reply.UpdateOption(dhcpv4.OptServerIdentifier(s.localIp))
	reply.UpdateOption(dhcpv4.OptMessage("requested address not available"))
	reply.SetBroadcast()
	reply.Options.Del(dhcpv4.OptionClientIdentifier)
	return reply, nil
}

// 构建一个完整的单播包（eth、ipv4、udp、payload），并发送
func (s *dhcpd) sendUnicast(peer *net.UDPAddr, m *dhcpv4.DHCPv4, payload *dhcpv4.DHCPv4) error {
	eth, ipv4, udp := s.createUnicastLayer(
		s.genIP(m.ClientHWAddr),
		m.ClientHWAddr,
		layers.UDPPort(peer.Port),
	)
	// 构建数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, opts,
		eth,
		ipv4,
		udp,
		gopacket.Payload(payload.ToBytes()),
	)
	// 打开网络接口
	handle, err := pcap.OpenLive(s.ifname, 65535, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()
	// 发送数据包
	data := buffer.Bytes()
	printHex(data)
	return handle.WritePacketData(data)
}

// 以带有空格的格式打印出每个字节的十六进制表示
func printHex(data []byte) {
	for i, b := range data {
		fmt.Printf("%02x ", b)
		// 每8个字节后换行
		if (i+1)%8 == 0 {
			fmt.Printf(" ")
		}
		if (i+1)%16 == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Println()
}

// 把ip从slice转换为可比较(==)的数组
func ipToComparator(in []byte) [4]byte {
	var out [4]byte
	copy(out[:], in)
	return out
}

func CreateServer(ifname string) error {
	var dhcpd0 = dhcpd{
		ifname:     ifname,
		serverPort: dhcpv4.ServerPort,
		macs:       sync.SyncList[[6]byte]{},
	}
	var err error
	dhcpd0.localIp, dhcpd0.localMask, dhcpd0.localMac, err = netlink.GetLocalInterface(dhcpd0.ifname)
	if err != nil {
		return err
	}
	if ipToComparator(dhcpd0.localMask) != ipToComparator(net.IPMask{255, 255, 255, 0}) {
		return fmt.Errorf("网卡 %s 配置的子网掩码不是255.255.255.0", ifname)
	}
	laddr := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: dhcpd0.serverPort,
	}
	server, err := server4.NewServer(ifname, laddr, dhcpd0.handler)
	if err != nil {
		return err
	}
	return server.Serve()
}
