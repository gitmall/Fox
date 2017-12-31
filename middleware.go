package fox

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/urfave/negroni"
)

type (
	Log struct{}
	Rec struct{}
)

func (l *Log) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	t := time.Now()
	next(w, r)
	res := w.(negroni.ResponseWriter)
	log.SetPrefix("[Fox] ")
	log.Printf("| %v | %v | %v | %v | content-length: %v",
		r.Method,
		res.Status(),
		r.URL.String(),
		time.Now().Sub(t).String(),
		res.Size())
	log.SetPrefix("")
}
func NewLog() *Log {
	return &Log{}
}

func (rec *Rec) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			debug.PrintStack()
			w.WriteHeader(500) // 500
		}
	}()
	next(w, r)
}
func NewRec() *Rec {
	return &Rec{}
}
