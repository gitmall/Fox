package fox

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"time"
)

func Logger(w ResponseWriteReader, r *http.Request, next func()) {
	t := time.Now()
	next()
	log.SetPrefix("[Fox] ")
	log.Printf("| %v | %v | %v | %v | content-length: %v",
		r.Method,
		w.StatusCode(),
		r.URL.String(),
		time.Now().Sub(t).String(),
		w.ContentLength())
	log.SetPrefix("")
}

func Recovery(w ResponseWriteReader, r *http.Request, next func()) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			debug.PrintStack()
			w.WriteHeader(500) // 500
		}
	}()
	next()
}
