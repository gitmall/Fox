package fox

import (
	"log"
	"net/http"
	"os"
)

// ResponseWriteReader for middleware
type ResponseWriteReader interface {
	StatusCode() int
	ContentLength() int
	http.ResponseWriter
}

// WrapResponseWriter implement ResponseWriteReader interface
type WrapResponseWriter struct {
	status int
	length int
	http.ResponseWriter
}

// NewWrapResponseWriter create wrapResponseWriter
func NewWrapResponseWriter(w http.ResponseWriter) *WrapResponseWriter {
	wr := new(WrapResponseWriter)
	wr.ResponseWriter = w
	wr.status = 200
	return wr
}

// WriteHeader write status code
func (p *WrapResponseWriter) WriteHeader(status int) {
	p.status = status
	p.ResponseWriter.WriteHeader(status)
}

func (p *WrapResponseWriter) Write(b []byte) (int, error) {
	n, err := p.ResponseWriter.Write(b)
	p.length += n
	return n, err
}

// StatusCode return status code
func (p *WrapResponseWriter) StatusCode() int {
	return p.status
}

// ContentLength return content length
func (p *WrapResponseWriter) ContentLength() int {
	return p.length
}

// MiddlewareFunc filter type
type MiddlewareFunc func(ResponseWriteReader, *http.Request, func())

// MiddlewareServe server struct
type Fox struct {
	middlewares []MiddlewareFunc
	Handler     http.Handler
	*Router
}

// ServeHTTP for http.Handler interface
func (f *Fox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i := 0
	wr := NewWrapResponseWriter(w)
	var next func()
	next = func() {
		if i < len(f.middlewares) {
			i++
			f.middlewares[i-1](wr, r, next)
		} else if f.Handler != nil {
			f.Handler.ServeHTTP(wr, r)
		}
	}
	next()
}

// Use push MiddlewareFunc
func (f *Fox) Use(funcs ...MiddlewareFunc) {
	for _, fc := range funcs {
		f.middlewares = append(f.middlewares, fc)
	}
}

func New() *Fox {
	var f Fox
	f.Router = Route()
	f.UseHandler(f.Router)
	return &f
}

func Default() *Fox {
	f := New()
	f.Use(Logger, Recovery)
	return f
}

func (f *Fox) UseHandler(h http.Handler) {
	f.Handler = h
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
func (f *Fox) Run(addr ...string) {
	l := log.New(os.Stdout, "[Fox] ", 0)
	finalAddr := detectAddress(addr...)
	l.Printf("listening on %s", finalAddr)
	l.Fatal(http.ListenAndServe(finalAddr, f))
}

func detectAddress(addr ...string) string {
	if len(addr) > 0 {
		return addr[0]
	}
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8000"
}
