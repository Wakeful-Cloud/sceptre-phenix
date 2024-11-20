package tmpl

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"text/template"

	sprig "github.com/go-task/slim-sprig/v3"
)

// GenerateFromTemplate executes the template with the given name using the
// given data. The result is written to the given writer. The templates used are
// located in the `phenix/tmpl/templates' directory. Each template will have a
// function with the signature `add(int, int)` available to it via a
// `template.FuncMap`. It returns any errors encountered while executing the
// template.
func GenerateFromTemplate(name string, data interface{}, w io.Writer) error {
	funcs := sprig.TxtFuncMap()

	funcs["cidrToMask"] = func(cidr string) string {
		_, ipv4Net, err := net.ParseCIDR(cidr)
		if err != nil {
			return "0.0.0.0"
		}

		// CIDR to four byte mask
		mask := ipv4Net.Mask

		return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}

	funcs["contains"] = func(value any, items []any) bool {
		// Convert to string
		strValue := reflect.ValueOf(value).String()

		for _, item := range items {
			// Convert to string
			strItem := reflect.ValueOf(item).String()

			if strValue == strItem {
				return true
			}
		}

		return false
	}

	funcs["prefixLines"] = func(prefix string, raw string) string {
		// Split by newline
		lines := strings.Split(raw, "\n")

		// Add prefix to each line
		for i, line := range lines {
			lines[i] = prefix + line
		}

		// Join lines back together
		return strings.Join(lines, "\n")
	}

	funcs["derefBool"] = func(boolean *bool) bool {
		if boolean == nil {
			return false
		}

		return *boolean
	}

	funcs["toBool"] = func(value interface{}) bool {
		switch v := value.(type) {
		case string:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return false
			}

			return b
		case int:
			return v != 0
		case bool:
			return v
		default:
			return false
		}
	}

	tmpl := template.Must(template.New(name).Funcs(funcs).Parse(string(MustAsset(name))))

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("executing %s template: %w", name, err)
	}

	return nil
}

// CreateFileFromTemplate executes the template with the given name using the
// given data. The result is written to the given file. Internally it calls
// `GenerateFromTemplate`. It returns any errors encountered while executing the
// template.
func CreateFileFromTemplate(name string, data interface{}, filename string) error {
	dir := filepath.Dir(filename)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating template path: %w", err)
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("creating template file: %w", err)
	}

	defer f.Close()

	return GenerateFromTemplate(name, data, f)
}
