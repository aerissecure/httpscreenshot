package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/freb/go-nmap"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/stealth"
	"github.com/integrii/flaggy"
	"github.com/maruel/natural"
)

// TODO:
// - create unique id's for each element (image hash?), then leave the src
// blank for each, setting them in a script at the end?:
// https://stackoverflow.com/questions/35149719/html-image-src-call-javascript-variable
// The goal is to combine identical images

var (
	logErr = log.New(os.Stderr, "", log.Flags()&^(log.Ldate|log.Ltime))
	logOut = log.New(os.Stdout, "", log.Flags()&^(log.Ldate|log.Ltime)) // todo, add more options and colorize?
)

type Config struct {
	NmapXML          []string
	AllHostnames     bool
	Bin              string
	Headless         bool
	OutFile          string
	Overwrite        bool
	IgnoreCerts      bool
	Trace            bool
	DisableIncognito bool
	Debug            bool
}

var conf = &Config{
	Headless:    true,
	OutFile:     "http-sshots.html",
	IgnoreCerts: true,
}

type Target struct {
	Scheme string
	Host   string
	Port   int
}

type Targets []*Target

func (t *Targets) Add(targets ...*Target) {
	empty := len(*t) == 0
	// Only add unique host+port.
	for _, target := range targets {
		if empty {
			fmt.Println("adding:", target)
			*t = append(*t, target)
			continue
		}
		skip := false
		for _, tgt := range *t {
			if tgt.Host == target.Host && tgt.Port == target.Port {
				skip = true
			}
		}
		if !skip {
			fmt.Println("adding:", target)
			*t = append(*t, target)
		}
	}
	t.Sort()
}

func (t Targets) Sort() {
	sort.SliceStable(t, func(i, j int) bool {
		return natural.Less(
			fmt.Sprintf("%s:%d", t[i].Host, t[i].Port),
			fmt.Sprintf("%s:%d", t[j].Host, t[j].Port),
		)
	})
}

func (t Target) String() string {
	return fmt.Sprintf("%s://%s:%d", t.Scheme, t.Host, t.Port)
}

func targetsFromNmapRun(nr nmap.NmapRun) Targets {
	var targets Targets

	for _, host := range nr.Hosts {
		for _, port := range host.Ports {
			if !strings.HasPrefix(port.Service.Name, "http") {
				continue
			}
			scheme := "http"
			if port.Service.Tunnel == "ssl" {
				scheme = "https"
			}

			// TODO: Add an option to skip IP if a hostnames is found for it.
			// Problem is we can't know if a user specified both a hostname and its
			// IP address.

			// Add all IPs.
			for _, addr := range host.Addresses {
				targets.Add(&Target{scheme, addr.Addr, port.PortId})
				fmt.Println("JUST ADDED:", targets)
			}

			for _, hostname := range host.Hostnames {
				// Type user indicates the hostname was explicity targeted, always add.
				if hostname.Type == "user" {
					targets.Add(&Target{scheme, hostname.Name, port.PortId})
					continue
				}

				// Add other hostnames if AllHostnames set and the hostname resolves.
				if conf.AllHostnames {
					if _, err := net.LookupHost(hostname.Name); err == nil {
						targets.Add(&Target{scheme, hostname.Name, port.PortId})
					} else if conf.Debug {
						fmt.Println("failed to resolve:", hostname.Name)
					}
				}
			}
		}
	}

	return targets
}

var htmlIntro = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>HTTP Screenshots</title>
  </head>
  <body>
`

var htmlOutro = `
  </body>
</html>
`

var htmlImage = `
<a href='%s' target=_blank style='font-size:x-large'>
%s
</a>
<br>
<img src='data:image/png;base64,%s' width=400 border=1 style='max-width:1024; margin-top:5px;'
 onclick='this.setAttribute("width", this.getAttribute("width") === "400" ? "100%%" : "400")' />
<hr style="margin:20px 0 20px 0">
`

func main() {
	flaggy.StringSlice(&conf.NmapXML, "n", "nmap-xml", "Nmap XML file")
	flaggy.Bool(&conf.AllHostnames, "a", "all-hostnames", "Use all known hostnames")
	flaggy.String(&conf.Bin, "b", "bin", "Path to Chrome binary")
	flaggy.Bool(&conf.Headless, "", "headless", "Run Chrome in headless mode")
	flaggy.String(&conf.OutFile, "o", "out", "Output file")
	flaggy.Bool(&conf.Overwrite, "", "overwrite", "Overwrite output file if it exists")
	flaggy.Bool(&conf.IgnoreCerts, "i", "ignore-certs", "Ignore certificate errors")
	flaggy.Bool(&conf.Trace, "", "trace", "")
	flaggy.Bool(&conf.DisableIncognito, "", "disable-incognito", "")
	flaggy.Bool(&conf.Debug, "", "debug", "")
	flaggy.Parse()

	var targets Targets

	if len(conf.NmapXML) > 0 {
		for _, nxmlfile := range conf.NmapXML {
			file, err := os.Open(nxmlfile)
			if err != nil {
				logErr.Fatalf("error opening file %s: %v\n", nxmlfile, err)
			}
			b, err := ioutil.ReadAll(file)
			if err != nil {
				logErr.Fatalf("error reading file %s: %v\n", nxmlfile, err)
			}

			nmapRun, err := nmap.Parse(b)
			if err != nil {
				logErr.Fatalf("error parsing file %s: %v\n", nxmlfile, err)
			}
			fmt.Println(nmapRun.Targets)
			targets.Add(targetsFromNmapRun(*nmapRun)...)
			fmt.Println("targets:", targets)
		}
	}

	if len(targets) == 0 {
		logErr.Fatalln("error, no targets specified")
	}

	if _, err := os.Stat(conf.OutFile); err == nil && !conf.Overwrite {
		logErr.Fatalln("file already exists, exiting:", conf.OutFile)
	}

	fmt.Println("List of targets:")
	for _, t := range targets {
		fmt.Println(t)
	}
	fmt.Println()

	doc, err := os.OpenFile(conf.OutFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	doc.WriteString(htmlIntro)
	defer func() {
		doc.WriteString(htmlOutro)
		doc.Close()
	}()

	l := launcher.New()
	l = l.Headless(conf.Headless)
	// If you don't specify .Bin(), it will download a browser to run for the platform.
	if conf.Bin != "" {
		l = l.Bin(conf.Bin)
	}

	u, err := l.Launch()
	if err != nil {
		logErr.Fatalf("error launching chrome: %v\n", err)
	}

	browser := rod.New().
		ControlURL(u).
		MustConnect().
		Trace(conf.Trace).
		MustIgnoreCertErrors(conf.IgnoreCerts)
	if !conf.DisableIncognito {
		browser = browser.MustIncognito()
	}
	defer browser.MustClose()

	page := stealth.MustPage(browser)
	defer page.MustClose()

	for _, t := range targets {
		logOut.Printf("capturing: %s", t)

		if err := page.Navigate(t.String()); err != nil {
			logErr.Printf("error navigating to %s: %v\n", t, err)
			continue
		}
		if err := page.WaitLoad(); err != nil {
			logErr.Printf("error waiting to load %s: %v\n", t, err)
			continue
		}

		sshotb, err := page.Screenshot(true, nil)
		if err != nil {
			logErr.Printf("error capturing: %s: %v\n", t.String(), err)
			continue
		}

		doc.WriteString(fmt.Sprintf(htmlImage, t.String(), t.String(), base64.StdEncoding.EncodeToString(sshotb)))

	}

}
