//go:build linux

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var fname = flag.String("r", "eth0", "Filename to read from")

type MyFormatter struct{}

func (m *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	timestamp := entry.Time.Format("20060102 15:04:05.999999")
	if entry.HasCaller() {
		fName := filepath.Base(entry.Caller.File)
		fmt.Fprintf(b, "%-24s %s %s %s:%d \n", timestamp, entry.Level, entry.Message, fName, entry.Caller.Line)
	} else {
		fmt.Fprintf(b, "%-24s %s %s\n", timestamp, entry.Level, entry.Message)
	}

	return b.Bytes(), nil
}

func ConfigLoger() {
	logger := &lumberjack.Logger{
		Filename:   "dns.log",
		MaxSize:    10,
		MaxBackups: 5,
		MaxAge:     28,
	}

	writers := []io.Writer{os.Stdout, logger}

	fileAndStdoutWriter := io.MultiWriter(writers...)

	logrus.SetOutput(fileAndStdoutWriter)
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&MyFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

func main() {
	flag.Parse()
	ConfigLoger()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	pcapFile := *fname
	if len(pcapFile) != 0 {
		if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
			handle, err := pcap.OpenLive(pcapFile, 65536, true, pcap.BlockForever)
			if err != nil {
				logrus.Errorf("PCAP OpenLive error %s", err.Error())
				return
			}
			go handlePcap(handle, stopper)
		} else {
			handle, err := pcap.OpenOffline(pcapFile)
			if err != nil {
				logrus.Errorf("PCAP OpenOffline error %s", err.Error())
			}
			go handlePcap(handle, stopper)
		}
	}
	// Wait
	<-stopper
	logrus.Info("stop")
	time.Sleep(100 * time.Millisecond)
}

func handlePcap(handle *pcap.Handle, stopper <-chan os.Signal) {
	handle.SetBPFFilter("udp and port 53")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	defer handle.Close()
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}
			handlePacket(packet)
		case <-stopper:
			return
		}
	}
}

type DNSPacket struct {
	Timestamp     time.Time
	SrcIP         string
	DstIP         string
	SrcPort       string
	DstPort       string
	TransactionID uint16
	IsResponse    bool
	Questions     []DNSQuestion
	Answers       []DNSAnswer
}

type DNSQuestion struct {
	Name  string
	Type  string
	Class string
}

type DNSAnswer struct {
	Name string
	Type string
	Data string
	TTL  uint32
}

func handlePacket(packet gopacket.Packet) {
	var dnsPkt DNSPacket
	dnsPkt.Timestamp = time.Now()

	// IP layer
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		dnsPkt.SrcIP = ip4.SrcIP.String()
		dnsPkt.DstIP = ip4.DstIP.String()
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		dnsPkt.SrcIP = ip6.SrcIP.String()
		dnsPkt.DstIP = ip6.DstIP.String()
	}

	// UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		dnsPkt.SrcPort = fmt.Sprintf("%d", udp.SrcPort)
		dnsPkt.DstPort = fmt.Sprintf("%d", udp.DstPort)
	}

	// DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		logrus.Warn("Not a DNS packet")
		return
	}
	dns := dnsLayer.(*layers.DNS)

	dnsPkt.TransactionID = dns.ID
	dnsPkt.IsResponse = dns.QR

	for _, q := range dns.Questions {
		dnsPkt.Questions = append(dnsPkt.Questions, DNSQuestion{
			Name:  string(q.Name),
			Type:  q.Type.String(),
			Class: q.Class.String(),
		})
	}

	for _, a := range dns.Answers {
		var data string
		switch a.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			data = a.IP.String()
		case layers.DNSTypeCNAME:
			data = string(a.CNAME)
		case layers.DNSTypeNS:
			data = string(a.NS)
		case layers.DNSTypePTR:
			data = string(a.PTR)
		case layers.DNSTypeTXT:
			if len(a.TXTs) > 0 {
				data = string(a.TXTs[0])
			}
		default:
			data = "<unsupported>"
		}

		dnsPkt.Answers = append(dnsPkt.Answers, DNSAnswer{
			Name: string(a.Name),
			Type: a.Type.String(),
			Data: data,
			TTL:  a.TTL,
		})
	}

	// 打印结构体内容
	logrus.Infof("DNSPacket: %+v", dnsPkt)
}
