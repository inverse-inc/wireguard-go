package services

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)


func main() {
	s, _ := GetServices()
	fmt.Printf("%v", s)
}

func (p *Service) String() string {
	return fmt.Sprintf("{Proto:%s Name: %s Port: %d}", p.Proto, p.Name, p.Port)
}

type Service struct {
	Proto string
	Name  string
	Port  uint16
}

type ServiceMap map[string]map[string]Service

const SERVICES_FILE = "/etc/services"

func GetServices() (ServiceMap, error) {
	file, err := os.Open(SERVICES_FILE)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	service_map := make(ServiceMap)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			// ignore comments
			continue
		}
		line = strings.TrimSpace(line)
		split := strings.SplitN(line, "#", 2)
		fields := strings.Fields(split[0])
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		portproto := strings.SplitN(fields[1], "/", 2)
		port, err := strconv.ParseInt(portproto[0], 10, 32)
		if err != nil {
			panic(err)
		}
		proto := portproto[1]
        proto_map := service_map[name]
        if proto_map == nil {
            proto_map = make(map[string]Service)
            service_map[name] = proto_map
        }
        
        proto_map[proto] = Service{
				Name:  name,
				Proto: proto,
				Port:  uint16(port),
        }
	}

	return service_map, nil
}

