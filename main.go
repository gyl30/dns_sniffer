package main

import (
	"bytes"
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

//go:embed web/*
var staticFiles embed.FS

var (
	fname           = flag.String("r", "eth0", "Interface or PCAP file")
	gdb             *gorm.DB
	packetChan      chan InputPacket
	pendingRequests = make(map[uint16]time.Time)
	pendingLock     sync.RWMutex
)

const (
	batchSize    = 100
	batchTimeout = 1 * time.Second
)

type DNSPacket struct {
	ID             uint      `gorm:"primaryKey"`
	Timestamp      time.Time `gorm:"index"`
	SrcIP          string
	DstIP          string
	SrcPort        int
	DstPort        int
	TransactionID  uint16
	IsResponse     bool
	ResponseTimeMs *int64
	Questions      []DNSQuestion `gorm:"foreignKey:PacketID"`
	Answers        []DNSAnswer   `gorm:"foreignKey:PacketID"`
}

type DNSName struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"uniqueIndex"`
}

type DNSQuestion struct {
	ID       uint `gorm:"primaryKey"`
	PacketID uint `gorm:"index"`
	NameID   uint `gorm:"index"`
	Type     string
	Class    string
}

type DNSAnswer struct {
	ID       uint `gorm:"primaryKey"`
	PacketID uint `gorm:"index"`
	NameID   uint `gorm:"index"`
	Type     string
	Data     string
	TTL      uint32
}

type InputPacket struct {
	Timestamp      time.Time
	SrcIP          string
	DstIP          string
	SrcPort        int
	DstPort        int
	TransactionID  uint16
	IsResponse     bool
	Questions      []InputQuestion
	Answers        []InputAnswer
	ResponseTimeMs int64
}

type (
	InputQuestion struct{ Name, Type, Class string }
	InputAnswer   struct {
		Name, Type, Data string
		TTL              uint32
	}
)

type MyFormatter struct{}

func (m *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}
	timestamp := entry.Time.Format("2006-01-02 15:04:05.000000")
	if entry.HasCaller() {
		fName := filepath.Base(entry.Caller.File)
		fmt.Fprintf(b, "%-24s %s %s %s:%d\n", timestamp, entry.Level, entry.Message, fName, entry.Caller.Line)
	} else {
		fmt.Fprintf(b, "%-24s %s %s\n", timestamp, entry.Level, entry.Message)
	}
	return b.Bytes(), nil
}

func ConfigLogger() {
	logOutput := &lumberjack.Logger{
		Filename:   "dns.log",
		MaxSize:    10,
		MaxBackups: 5,
		MaxAge:     28,
	}
	logrus.SetOutput(io.MultiWriter(os.Stdout, logOutput))
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&MyFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

func InitDB() error {
	var err error
	gormLogger := logger.New(
		logrus.StandardLogger(),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Info,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	gdb, err = gorm.Open(sqlite.Open("dns.db"), &gorm.Config{
		Logger:                                   gormLogger,
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	logrus.Info("Running GORM AutoMigrate (with foreign key constraints disabled)...")
	err = gdb.AutoMigrate(&DNSPacket{}, &DNSName{}, &DNSQuestion{}, &DNSAnswer{})
	if err != nil {
		return fmt.Errorf("failed to auto-migrate database: %w", err)
	}
	logrus.Info("Database migration completed.")
	return nil
}

func saveBatch(packets []InputPacket) {
	if len(packets) == 0 {
		return
	}
	start := time.Now()

	err := gdb.Transaction(func(tx *gorm.DB) error {
		nameCache := make(map[string]uint)

		gormPackets := make([]DNSPacket, 0, len(packets))
		gormQuestions := make([]DNSQuestion, 0, len(packets))
		gormAnswers := make([]DNSAnswer, 0, len(packets))

		for _, pkt := range packets {
			gormPkt := DNSPacket{
				Timestamp:     pkt.Timestamp,
				SrcIP:         pkt.SrcIP,
				DstIP:         pkt.DstIP,
				SrcPort:       pkt.SrcPort,
				DstPort:       pkt.DstPort,
				TransactionID: pkt.TransactionID,
				IsResponse:    pkt.IsResponse,
			}
			if pkt.ResponseTimeMs >= 0 {
				rt := pkt.ResponseTimeMs
				gormPkt.ResponseTimeMs = &rt
			}
			gormPackets = append(gormPackets, gormPkt)
		}

		if err := tx.Create(&gormPackets).Error; err != nil {
			return fmt.Errorf("batch insert packets failed: %w", err)
		}

		for i, pkt := range packets {
			packetID := gormPackets[i].ID

			for _, q := range pkt.Questions {
				lowerName := strings.ToLower(q.Name)
				nameID, ok := nameCache[lowerName]
				if !ok {
					var dnsName DNSName
					if err := tx.Where(DNSName{Name: lowerName}).FirstOrCreate(&dnsName).Error; err != nil {
						return fmt.Errorf("get or create name '%s' failed: %w", lowerName, err)
					}
					nameID = dnsName.ID
					nameCache[lowerName] = nameID
				}
				gormQuestions = append(gormQuestions, DNSQuestion{
					PacketID: packetID,
					NameID:   nameID,
					Type:     q.Type,
					Class:    q.Class,
				})
			}

			for _, a := range pkt.Answers {
				lowerName := strings.ToLower(a.Name)
				nameID, ok := nameCache[lowerName]
				if !ok {
					var dnsName DNSName
					if err := tx.Where(DNSName{Name: lowerName}).FirstOrCreate(&dnsName).Error; err != nil {
						return fmt.Errorf("get or create name '%s' failed: %w", lowerName, err)
					}
					nameID = dnsName.ID
					nameCache[lowerName] = nameID
				}
				gormAnswers = append(gormAnswers, DNSAnswer{
					PacketID: packetID,
					NameID:   nameID,
					Type:     a.Type,
					Data:     a.Data,
					TTL:      a.TTL,
				})
			}
		}

		if len(gormQuestions) > 0 {
			if err := tx.Create(&gormQuestions).Error; err != nil {
				return fmt.Errorf("batch insert questions failed: %w", err)
			}
		}
		if len(gormAnswers) > 0 {
			if err := tx.Create(&gormAnswers).Error; err != nil {
				return fmt.Errorf("batch insert answers failed: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		logrus.Errorf("saveBatch: transaction failed, rolled back: %v", err)
	} else {
		logrus.Infof("saveBatch: finished saving a batch of %d packets, total cost=%v", len(packets), time.Since(start))
	}
}

func packetProcessor() {
	var batch []InputPacket
	ticker := time.NewTicker(batchTimeout)
	defer ticker.Stop()
	for {
		select {
		case pkt, ok := <-packetChan:
			if !ok {
				logrus.Info("packetProcessor: packetChan closed, saving remaining batch.")
				saveBatch(batch)
				return
			}
			batch = append(batch, pkt)
			if len(batch) >= batchSize {
				saveBatch(batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				saveBatch(batch)
				batch = nil
			}
		}
	}
}

func handlePcap(handle *pcap.Handle, stopper <-chan os.Signal) {
	handle.SetBPFFilter("udp and port 53")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	defer handle.Close()
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				return
			}
			handlePacket(packet)
		case <-stopper:
			return
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns := dnsLayer.(*layers.DNS)
	var responseTimeMs int64 = -1
	if !dns.QR {
		pendingLock.Lock()
		pendingRequests[dns.ID] = packet.Metadata().Timestamp
		pendingLock.Unlock()
	} else {
		pendingLock.RLock()

		requestTime, ok := pendingRequests[dns.ID]
		pendingLock.RUnlock()
		if ok {
			responseTimeMs = packet.Metadata().Timestamp.Sub(requestTime).Milliseconds()
			pendingLock.Lock()
			delete(pendingRequests, dns.ID)
			pendingLock.Unlock()
		}
	}

	var pkt InputPacket
	pkt.Timestamp = packet.Metadata().Timestamp
	pkt.TransactionID = dns.ID
	pkt.IsResponse = dns.QR
	pkt.ResponseTimeMs = responseTimeMs

	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ip := ip4.(*layers.IPv4)
		pkt.SrcIP, pkt.DstIP = ip.SrcIP.String(), ip.DstIP.String()
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ip := ip6.(*layers.IPv6)
		pkt.SrcIP, pkt.DstIP = ip.SrcIP.String(), ip.DstIP.String()
	}

	if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		pkt.SrcPort, pkt.DstPort = int(u.SrcPort), int(u.DstPort)
	}

	for _, q := range dns.Questions {
		pkt.Questions = append(pkt.Questions, InputQuestion{Name: string(q.Name), Type: q.Type.String(), Class: q.Class.String()})
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
		pkt.Answers = append(pkt.Answers, InputAnswer{Name: string(a.Name), Type: a.Type.String(), Data: data, TTL: a.TTL})
	}

	select {
	case packetChan <- pkt:
	default:
		logrus.Warnf("handlePacket: packetChan is full, dropping DNS packet TxID=%d", pkt.TransactionID)
	}
}

func main() {
	flag.Parse()
	ConfigLogger()
	if err := InitDB(); err != nil {
		logrus.Fatalf("DB init failed: %v", err)
	}

	packetChan = make(chan InputPacket, 1000)
	go packetProcessor()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	pcapFile := *fname
	if len(pcapFile) != 0 {
		if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
			logrus.Infof("Starting capture on interface: %s", pcapFile)
			handle, err := pcap.OpenLive(pcapFile, 65536, true, pcap.BlockForever)
			if err != nil {
				logrus.Fatalf("PCAP OpenLive error: %s", err)
			}
			go handlePcap(handle, stopper)
		} else {
			logrus.Infof("Opening offline capture file: %s", pcapFile)
			handle, err := pcap.OpenOffline(pcapFile)
			if err != nil {
				logrus.Fatalf("PCAP OpenOffline error: %s", err)
			}
			go handlePcap(handle, stopper)
		}
	}

	go startWebServer()
	<-stopper
	logrus.Info("Stopping...")
	close(packetChan)
	time.Sleep(2 * time.Second)
	logrus.Info("Shutdown complete.")
}

func startWebServer() {
	webFS, err := fs.Sub(staticFiles, "web")
	if err != nil {
		logrus.Fatal(err)
	}

	http.Handle("/", http.FileServer(http.FS(webFS)))

	http.HandleFunc("/api/v2/overview/kpis", handleV2OverviewKPIs)
	http.HandleFunc("/api/v2/overview/timeseries", handleV2OverviewTimeseries)
	http.HandleFunc("/api/v2/overview/top-domains", handleV2OverviewTopDomains)
	http.HandleFunc("/api/v2/overview/top-servers", handleV2OverviewTopServers)
	http.HandleFunc("/api/v2/overview/details", handleV2DomainDetails)
	http.HandleFunc("/api/v2/overview/server-details", handleV2ServerDetails)

	logrus.Info("Starting web server on :8183")
	if err := http.ListenAndServe(":8183", nil); err != nil {
		logrus.Fatalf("Web server failed: %v", err)
	}
}

func parseRangeToTime(r *http.Request) time.Time {
	switch r.URL.Query().Get("range") {
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		return time.Now().Add(-30 * 24 * time.Hour)
	default:
		return time.Now().Add(-24 * time.Hour)
	}
}

func handleV2OverviewKPIs(w http.ResponseWriter, r *http.Request) {
	since := parseRangeToTime(r)

	var totalQueries, uniqueDomains int64
	var avgResponseMs sql.NullFloat64

	gdb.Model(&DNSPacket{}).Where("timestamp >= ? AND is_response = ?", since, false).Count(&totalQueries)

	gdb.Model(&DNSQuestion{}).
		Joins("JOIN dns_packets ON dns_packets.id = dns_questions.packet_id").
		Where("dns_packets.timestamp >= ?", since).
		Distinct("name_id").
		Count(&uniqueDomains)

	gdb.Model(&DNSPacket{}).
		Where("timestamp >= ? AND response_time_ms IS NOT NULL", since).
		Select("AVG(response_time_ms)").
		Scan(&avgResponseMs)

	var finalAvgMs int
	if avgResponseMs.Valid {
		finalAvgMs = int(avgResponseMs.Float64)
	} else {
		finalAvgMs = 0
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_queries":   totalQueries,
		"unique_domains":  uniqueDomains,
		"avg_response_ms": finalAvgMs,
	})
}

func handleV2OverviewTimeseries(w http.ResponseWriter, r *http.Request) {
	rangeParam := r.URL.Query().Get("range")
	var timeFormat string
	if rangeParam == "7d" || rangeParam == "30d" {
		timeFormat = `strftime('%Y-%m-%dT00:00:00', timestamp)`
	} else {
		timeFormat = `strftime('%Y-%m-%dT%H:00:00', timestamp)`
	}
	since := parseRangeToTime(r)

	var results []map[string]interface{}
	err := gdb.Model(&DNSPacket{}).
		Select(timeFormat+" as time_unit, COUNT(*) as count").
		Where("timestamp >= ? AND is_response = ?", since, false).
		Group("time_unit").
		Order("time_unit ASC").
		Find(&results).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleV2OverviewTopDomains(w http.ResponseWriter, r *http.Request) {
	since := parseRangeToTime(r)

	var results []map[string]interface{}
	err := gdb.Model(&DNSQuestion{}).
		Select("dns_names.name, COUNT(dns_questions.id) as count").
		Joins("JOIN dns_names ON dns_names.id = dns_questions.name_id").
		Joins("JOIN dns_packets ON dns_packets.id = dns_questions.packet_id").
		Where("dns_packets.timestamp >= ?", since).
		Group("dns_names.name").
		Order("count DESC").
		Limit(10).
		Find(&results).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleV2OverviewTopServers(w http.ResponseWriter, r *http.Request) {
	since := parseRangeToTime(r)

	var results []map[string]interface{}
	err := gdb.Model(&DNSPacket{}).
		Select("dst_ip as ip, COUNT(*) as count").
		Where("timestamp >= ? AND is_response = ?", since, false).
		Group("dst_ip").
		Order("count DESC").
		Limit(10).
		Find(&results).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleV2DomainDetails(w http.ResponseWriter, r *http.Request) {
	domainName := r.URL.Query().Get("name")
	if domainName == "" {
		http.Error(w, "missing 'name' query parameter", http.StatusBadRequest)
		return
	}
	since := parseRangeToTime(r)
	lowerDomainName := strings.ToLower(domainName)

	type DetailResult struct {
		Timestamp  time.Time `json:"timestamp"`
		DnsServer  string    `json:"dns_server"`
		Latency    *int64    `json:"-"`
		LatencyStr string    `json:"latency"`
	}

	var results []DetailResult
	err := gdb.Model(&DNSPacket{}).
		Select("dns_packets.timestamp, dns_packets.dst_ip as dns_server, dns_packets.response_time_ms as latency").
		Joins("JOIN dns_questions ON dns_questions.packet_id = dns_packets.id").
		Joins("JOIN dns_names ON dns_names.id = dns_questions.name_id").
		Where("dns_names.name = ? AND dns_packets.timestamp >= ? AND dns_packets.is_response = ?", lowerDomainName, since, true).
		Order("dns_packets.timestamp DESC").
		Limit(100).
		Scan(&results).Error
	if err != nil {
		logrus.Errorf("[Details API] DB query execution failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for i := range results {
		if results[i].Latency != nil {
			results[i].LatencyStr = fmt.Sprintf("%d", *results[i].Latency)
		} else {
			results[i].LatencyStr = "N/A"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleV2ServerDetails(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	serverIP := r.URL.Query().Get("ip")
	if serverIP == "" {
		http.Error(w, "missing 'ip' query parameter", http.StatusBadRequest)
		return
	}

	since := parseRangeToTime(r)

	var results []map[string]interface{}
	err := gdb.Model(&DNSQuestion{}).
		Select("dns_names.name, COUNT(dns_questions.id) as count").
		Joins("JOIN dns_names ON dns_names.id = dns_questions.name_id").
		Joins("JOIN dns_packets ON dns_packets.id = dns_questions.packet_id").
		Where("dns_packets.dst_ip = ? AND dns_packets.timestamp >= ? AND dns_packets.is_response = ?", serverIP, since, false).
		Group("dns_names.name").
		Order("count DESC").
		Limit(100).
		Find(&results).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(results)
}
