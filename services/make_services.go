// +build ignore

package main

import (
	"bytes"
	"fmt"
	"github.com/inverse-inc/wireguard-go/services"
	"go/format"
	"text/template"
)

func main() {
	t := template.New("")
	buffer := bytes.NewBuffer(nil)
	template := `package services

var SERVICE_MAP = ServiceMap{
        {{range $k, $v := .}}"{{$k}}" : map[string]Service{
            {{ range $p, $s := $v  }}"{{$p}}" : Service{
                    Proto:"{{$s.Proto}}",
                    Name:"{{$s.Name}}",
                    Port:{{$s.Port}},
                },
{{end}} },
{{end}}
    }
`
	t.Parse(template)
	s, _ := services.GetServices()
	t.Execute(buffer, s)
	formatted, err := format.Source(buffer.Bytes())
	if err != nil {
		fmt.Printf("Error: %s\n%s\n", err.Error(), buffer.Bytes())
	} else {
		fmt.Print(string(formatted))
	}

}
