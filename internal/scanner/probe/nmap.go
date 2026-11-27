package probe

import (
	"bytes"
	"context"
	"encoding/xml"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// NmapTimeout bounds one nmap run (one host, its open ports).
const NmapTimeout = 3 * time.Minute

// FindNmap returns the path of the nmap binary, or "" if it isn't installed.
func FindNmap() string {
	p, err := exec.LookPath("nmap")
	if err != nil {
		return ""
	}
	return p
}

type nmapRun struct {
	Hosts []struct {
		Ports []struct {
			PortID int `xml:"portid,attr"`
			State  struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name      string `xml:"name,attr"`
				Product   string `xml:"product,attr"`
				Version   string `xml:"version,attr"`
				ExtraInfo string `xml:"extrainfo,attr"`
				Tunnel    string `xml:"tunnel,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// nmapArgs scans exactly the given ports of one address: no host
// discovery (-Pn, the ports are known to be open), no DNS (-n), plain
// connect scan without raw sockets (--unprivileged), version detection
// (-sV), XML on stdout.
func nmapArgs(addr string, ports []int) []string {
	list := make([]string, len(ports))
	for i, p := range ports {
		list[i] = strconv.Itoa(p)
	}
	return []string{"-sV", "-Pn", "-n", "--unprivileged", "--version-intensity", "5",
		"--host-timeout", strconv.Itoa(int(NmapTimeout.Seconds())) + "s",
		"-p", strings.Join(list, ","), "-oX", "-", "--", addr}
}

// nmapServices runs nmap for one host. A failed run returns nothing; the
// caller then falls back to the built-in check.
func nmapServices(ctx context.Context, path, addr string, ports []int) map[int]Service {
	if len(ports) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, NmapTimeout+30*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, path, nmapArgs(addr, ports)...)
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil
	}
	return parseNmapXML(stdout.Bytes())
}

func parseNmapXML(data []byte) map[int]Service {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil
	}
	out := map[int]Service{}
	for _, h := range run.Hosts {
		for _, p := range h.Ports {
			sv := p.Service
			if p.State.State != "open" || sv.Name == "" {
				continue
			}
			name := sv.Name
			if sv.Tunnel == "ssl" && name == "http" {
				name = "https"
			}
			out[p.PortID] = Service{Name: name, Product: sv.Product, Version: sv.Version, Extra: sv.ExtraInfo, Method: "nmap"}
		}
	}
	return out
}
