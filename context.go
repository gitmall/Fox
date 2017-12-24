package fox

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/unrolled/render"
)

const base64Table = "+-*!ABYZabcghijklmnopqrstuvwxyz01EFGHIJKLMNOPQRSTU0123456789/<>?"

var (
	r     = render.New()
	coder = base64.NewEncoding(base64Table)
)

type (
	Context struct {
		Writer http.ResponseWriter
		Req    *http.Request
		Ps     Params
	}
	Dmap map[string]interface{}
)

func SetRender(options map[string]interface{}) error {
	op := render.Options{}
	for k, v := range options {
		if v != nil {
			err := setField(&op, k, v)
			if err != nil {
				return err
			}
		}
	}
	r = render.New(op)
	return nil
}
func setField(obj interface{}, name string, value interface{}) error {
	structValue := reflect.ValueOf(obj).Elem()
	structFieldValue := structValue.FieldByName(name)

	if !structFieldValue.IsValid() {
		return fmt.Errorf("No such field: %s in obj", name)
	}

	if !structFieldValue.CanSet() {
		return fmt.Errorf("Cannot set %s field value", name)
	}

	structFieldType := structFieldValue.Type()
	val := reflect.ValueOf(value)
	if structFieldType != val.Type() {
		return errors.New("Provided value type didn't match obj field type")
	}

	structFieldValue.Set(val)
	return nil
}
func SetDelims(left, right string) render.Delims {
	d := render.Delims{left, right}
	return d
}
func (c *Context) Json(status int, v interface{}) error {
	return r.JSON(c.Writer, status, v)
}
func (c *Context) Html(status int, name string, binding interface{}, htmlOpt ...render.HTMLOptions) error {
	return r.HTML(c.Writer, status, name, binding, htmlOpt...)
}
func (c *Context) Xml(status int, v interface{}) error {
	return r.XML(c.Writer, status, v)
}
func (c *Context) Text(status int, v string) error {
	return r.Text(c.Writer, status, v)
}
func (c *Context) Data(status int, v []byte) error {
	return r.Data(c.Writer, status, v)
}
func (c *Context) Cookie(name string) (*http.Cookie, error) {
	return c.Req.Cookie(name)
}

func (c *Context) SetCookie(cookie *http.Cookie) {
	http.SetCookie(c.Writer, cookie)
}
func (c *Context) SetSecureCookie(cookie *http.Cookie, salt string) {
	src := []byte(salt + cookie.Value)
	cookie.Value = string([]byte(coder.EncodeToString(src)))
	http.SetCookie(c.Writer, cookie)
}
func (c *Context) GetSecureCookie(name, salt string) (*http.Cookie, error) {
	ck, err := c.Req.Cookie(name)
	if err != nil {
		return nil, err
	}
	src := []byte(ck.Value)
	dstr, err := coder.DecodeString(string(src))
	ck.Value = strings.Replace(string(dstr), salt, "", -1)
	return ck, nil
}
func (c *Context) Param(key string) string {
	return c.Ps.ByName(key)
}

func (c *Context) Redirect(code int, location string) {
	http.Redirect(c.Writer, c.Req, location, code)
}
func (c *Context) Query(key string) string {
	value := c.Req.URL.Query().Get(key)
	return value
}
func (c *Context) DefaultQuery(key, defaultValue string) string {
	value := c.Query(key)
	if len(value) > 0 {
		return value
	}
	return defaultValue
}

// Maximum amount of memory to use when parsing a multipart form.
// Set this to whatever value you prefer; default is 10 MB.
var MaxMemory = int64(1024 * 1024 * 10)

func (c *Context) parseForm() {
	if c.Req.Form != nil {
		return
	}

	contentType := c.Req.Header.Get("Content-Type")
	if (c.Req.Method == "POST" || c.Req.Method == "PUT") &&
		len(contentType) > 0 && strings.Contains(contentType, "multipart/form-data") {
		c.Req.ParseMultipartForm(MaxMemory)
	} else {
		c.Req.ParseForm()
	}
}

// GetFile returns information about user upload file by given form field name.
func (c *Context) GetFile(name string) (multipart.File, *multipart.FileHeader, error) {
	return c.Req.FormFile(name)
}

// SaveToFile reads a file from request by field name and saves to given path.
func (c *Context) SaveToFile(name, savePath string) error {
	fr, _, err := c.GetFile(name)
	if err != nil {
		return err
	}
	defer fr.Close()

	fw, err := os.OpenFile(savePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer fw.Close()

	_, err = io.Copy(fw, fr)
	return err
}
