package kubernetes

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
	api "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func BenchmarkController(b *testing.B) {
	client := fake.NewSimpleClientset()
	dco := dnsControlOpts{
		zones: []string{"cluster.local."},
	}
	ctx := context.Background()
	controller := newdnsController(ctx, client, dco)
	cidr := "10.0.0.0/19"

	// Add resources
	generateEndpoints(cidr, client)
	generateSvcs(cidr, "all", client)
	m := new(dns.Msg)
	m.SetQuestion("svc1.testns.svc.cluster.local.", dns.TypeA)
	k := New([]string{"cluster.local."})
	k.APIConn = controller
	rw := &test.ResponseWriter{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.ServeDNS(ctx, rw, m)
	}
}

func generateEndpoints(cidr string, client kubernetes.Interface) {
	// https://groups.google.com/d/msg/golang-nuts/zlcYA4qk-94/TWRFHeXJCcYJ
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal(err)
	}

	count := 1
	ep := &api.Endpoints{
		Subsets: []api.EndpointSubset{{
			Ports: []api.EndpointPort{
				{
					Port:     80,
					Protocol: "tcp",
					Name:     "http",
				},
			},
		}},
		ObjectMeta: meta.ObjectMeta{
			Namespace: "testns",
		},
	}
	ctx := context.TODO()
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ep.Subsets[0].Addresses = []api.EndpointAddress{
			{
				IP:       ip.String(),
				Hostname: "foo" + strconv.Itoa(count),
			},
		}
		ep.ObjectMeta.Name = "svc" + strconv.Itoa(count)
		client.CoreV1().Endpoints("testns").Create(ctx, ep, meta.CreateOptions{})
		count++
	}
}

func generateSvcs(cidr string, svcType string, client kubernetes.Interface) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal(err)
	}

	count := 1
	switch svcType {
	case "clusterip":
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			createClusterIPSvc(count, client, ip)
			count++
		}
	case "headless":
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			createHeadlessSvc(count, client, ip)
			count++
		}
	case "external":
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			createExternalSvc(count, client, ip)
			count++
		}
	default:
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			if count%3 == 0 {
				createClusterIPSvc(count, client, ip)
			} else if count%3 == 1 {
				createHeadlessSvc(count, client, ip)
			} else if count%3 == 2 {
				createExternalSvc(count, client, ip)
			}
			count++
		}
	}
}

func createClusterIPSvc(suffix int, client kubernetes.Interface, ip net.IP) {
	ctx := context.TODO()
	client.CoreV1().Services("testns").Create(ctx, &api.Service{
		ObjectMeta: meta.ObjectMeta{
			Name:      "svc" + strconv.Itoa(suffix),
			Namespace: "testns",
		},
		Spec: api.ServiceSpec{
			ClusterIP: ip.String(),
			Ports: []api.ServicePort{{
				Name:     "http",
				Protocol: "tcp",
				Port:     80,
			}},
		},
	}, meta.CreateOptions{})
}

func createHeadlessSvc(suffix int, client kubernetes.Interface, ip net.IP) {
	ctx := context.TODO()
	client.CoreV1().Services("testns").Create(ctx, &api.Service{
		ObjectMeta: meta.ObjectMeta{
			Name:      "hdls" + strconv.Itoa(suffix),
			Namespace: "testns",
		},
		Spec: api.ServiceSpec{
			ClusterIP: api.ClusterIPNone,
		},
	}, meta.CreateOptions{})
}

func createExternalSvc(suffix int, client kubernetes.Interface, ip net.IP) {
	ctx := context.TODO()
	client.CoreV1().Services("testns").Create(ctx, &api.Service{
		ObjectMeta: meta.ObjectMeta{
			Name:      "external" + strconv.Itoa(suffix),
			Namespace: "testns",
		},
		Spec: api.ServiceSpec{
			ExternalName: "coredns" + strconv.Itoa(suffix) + ".io",
			Ports: []api.ServicePort{{
				Name:     "http",
				Protocol: "tcp",
				Port:     80,
			}},
			Type: api.ServiceTypeExternalName,
		},
	}, meta.CreateOptions{})
}
