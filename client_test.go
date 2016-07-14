package soap

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/achiku/testsvr"
	"github.com/achiku/xml"
)

type name struct {
	XMLName xml.Name `xml:"name"`
	First   string   `xml:"first,omitempty"`
	Last    string   `xml:"last,omitempty"`
}

type person struct {
	XMLName xml.Name `xml:"person"`
	ID      int      `xml:"id,omitempty"`
	Name    *name
	Age     int `xml:"age,omitempty"`
}

type myRequestHeader struct {
	XMLName  xml.Name `xml:"myRequestHeader"`
	UserID   string   `xml:"userId"`
	Password string   `xml:"password"`
}

type myResponseHeader struct {
	XMLName       xml.Name `xml:"myResponseHeader"`
	TransactionID string   `xml:"transactionId"`
}

type testRequest struct {
	Message string `xml:"message"`
}

func withSOAPFaultResponse(logger testsvr.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawbody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Logf("Received Request:\n%s", rawbody)
		v := Envelope{
			Body: Body{
				Fault: &Fault{
					Code:   "Error",
					Actor:  "Actor",
					Detail: "Something went wrong",
				},
			},
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusInternalServerError)
		res, _ := xml.MarshalIndent(v, "", "  ")
		logger.Logf("Response:\n%s", res)
		w.Write(res)
		return
	}
}

func noSOAPHeaderResponse(logger testsvr.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawbody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Logf("Received Request:\n%s", rawbody)
		v := Envelope{
			Body: Body{
				Content: person{
					ID:  1,
					Age: 22,
					Name: &name{
						Last:  "Mogami",
						First: "Moga",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		res, _ := xml.MarshalIndent(v, "", "  ")
		logger.Logf("Response:\n%s", res)
		w.Write(res)
		return
	}
}

func withSOAPHeaderResponse(logger testsvr.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawbody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Logf("Received Request:\n%s", rawbody)
		v := Envelope{
			Header: &Header{
				Content: myResponseHeader{
					TransactionID: "100",
				},
			},
			Body: Body{
				Content: person{
					ID:  1,
					Age: 22,
					Name: &name{
						Last:  "Mogami",
						First: "Moga",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		res, _ := xml.MarshalIndent(v, "", "  ")
		logger.Logf("Response:\n%s", res)
		w.Write(res)
		return
	}
}

var DefaultHandlerMap = map[string]testsvr.CreateHandler{
	"/noheader": noSOAPHeaderResponse,
	"/header":   withSOAPHeaderResponse,
	"/error":    withSOAPFaultResponse,
}

func TestClientNoSOAPHeader(t *testing.T) {
	ts := httptest.NewServer(testsvr.NewMux(DefaultHandlerMap, t))
	defer ts.Close()

	isTLS := false
	url := ts.URL + "/noheader"
	client := NewClient(url, isTLS, nil)
	req := testRequest{Message: "test"}
	resp := person{}
	if err := client.Call(url, req, &resp, nil); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", resp)
	if resp.ID != 1 {
		t.Errorf("want 1 got %d", resp.ID)
	}
}

func TestClientWithSOAPHeader(t *testing.T) {
	ts := httptest.NewServer(testsvr.NewMux(DefaultHandlerMap, t))
	defer ts.Close()

	isTLS := false
	url := ts.URL + "/header"
	header := myRequestHeader{
		UserID:   "myname",
		Password: "pass",
	}
	client := NewClient(url, isTLS, header)
	req := testRequest{Message: "test"}
	resp := person{}
	respHeader := myResponseHeader{}
	if err := client.Call(url, req, &resp, &respHeader); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", resp)
	t.Logf("%+v", respHeader)
	if resp.ID != 1 {
		t.Errorf("want 1 got %d", resp.ID)
	}
	if respHeader.TransactionID != "100" {
		t.Errorf("want 100 got %s", respHeader.TransactionID)
	}
}

func TestClientSOAPFault(t *testing.T) {
	ts := httptest.NewServer(testsvr.NewMux(DefaultHandlerMap, t))
	defer ts.Close()

	isTLS := false
	url := ts.URL + "/error"
	client := NewClient(url, isTLS, nil)
	req := testRequest{Message: "test"}
	resp := person{}
	err := client.Call(url, req, &resp, nil)
	if err == nil {
		t.Fatal("no error")
	}
	t.Log(err)
}
