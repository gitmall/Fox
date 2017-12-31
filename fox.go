package fox

import (
	"log"
	"net/http"
	"os"

	"github.com/urfave/negroni"
)

type Fox struct {
	*negroni.Negroni
	*Router
}

func New(handlers ...negroni.Handler) *Fox {
	var f Fox
	f.Negroni = negroni.New(handlers...)
	f.Router = Route()
	f.UseHandler(f.Router)
	return &f
}
func Classic() *Fox {
	return New(NewRec(), NewLog())
}

func (f *Fox) Run(addr ...string) {
	l := log.New(os.Stdout, "[Fox] ", 0)
	finalAddr := detectAddress(addr...)
	l.Printf("Webservice start and listening on %s", finalAddr)
	l.Fatal(http.ListenAndServe(finalAddr, f.Negroni))
}

func detectAddress(addr ...string) string {
	if len(addr) > 0 {
		return addr[0]
	}
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8080"
}

func (f *Fox) Static(path, dir string) {
	if lastChar(path) != '/' {
		path += "/"
	}
	path += "*filepath"
	f.ServeFiles(path, http.Dir(dir))
}
func lastChar(str string) uint8 {
	size := len(str)
	if size == 0 {
		panic("The length of the string can't be 0")
	}
	return str[size-1]
}
