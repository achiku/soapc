package soap

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io"
	"net/http"
	"sync"

	"github.com/kylewolfe/soaptrip"
	"github.com/pkg/errors"
)

// Envelope envelope
type Envelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Header  *Header  `xml:",omitempty"`
	Body    Body
}

// Header header
type Header struct {
	XMLName xml.Name    `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`
	Content interface{} `xml:",omitempty"`
}

// Body body
type Body struct {
	XMLName xml.Name    `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Fault   *Fault      `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

// Fault fault
type Fault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`
	Code    string   `xml:"faultcode,omitempty"`
	String  string   `xml:"faultstring,omitempty"`
	Actor   string   `xml:"faultactor,omitempty"`
	Detail  string   `xml:"detail,omitempty"`
}

func (f *Fault) Error() string {
	return f.String
}

// NewClient return SOAP client
func NewClient(url string, tlsSkipVerify bool, header interface{}) *Client {
	tr := http.DefaultTransport.(*http.Transport)
	if tlsSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: tlsSkipVerify}
	}
	return &Client{
		url:        url,
		header:     header,
		HTTPClient: &http.Client{Transport: soaptrip.New(tr)},
	}
}

// Client SOAP client
type Client struct {
	url        string
	userAgent  string
	header     interface{}
	HTTPClient *http.Client
}

// UnmarshalXML unmarshal SOAPHeader
func (h *Header) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var (
		token xml.Token
		err   error
	)
Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}
		if token == nil {
			break
		}
		switch se := token.(type) {
		case xml.StartElement:
			if err = d.DecodeElement(h.Content, &se); err != nil {
				return err
			}
		case xml.EndElement:
			break Loop
		}
	}
	return nil
}

// UnmarshalXML unmarshal SOAPBody
func (b *Body) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}
	var (
		token    xml.Token
		err      error
		consumed bool
	)
Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}
		if token == nil {
			break
		}
		envelopeNameSpace := "http://schemas.xmlsoap.org/soap/envelope/"
		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError(
					"Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == envelopeNameSpace && se.Name.Local == "Fault" {
				b.Fault = &Fault{}
				b.Content = nil
				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}
				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}
				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}
	return nil
}

var bufPool = sync.Pool{New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 1024)) }}

// Call SOAP client API call
func (s *Client) Call(soapAction string, request, response, header interface{}) error {
	var envelope Envelope
	if s.header != nil {
		envelope = Envelope{
			Header: &Header{Content: s.header},
			Body:   Body{Content: request},
		}
	} else {
		envelope = Envelope{
			Body: Body{Content: request},
		}
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	buf.Reset()
	encoder := xml.NewEncoder(buf)
	encoder.Indent("  ", "    ")
	if err := encoder.Encode(envelope); err != nil {
		return errors.Wrap(err, "failed to encode envelope")
	}
	if err := encoder.Flush(); err != nil {
		return errors.Wrap(err, "failed to flush encoder")
	}

	req, err := http.NewRequest("POST", s.url, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return errors.Wrap(err, "failed to create POST request")
	}
	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", soapAction)
	if s.userAgent != "" {
		req.Header.Set("User-Agent", s.userAgent)
	}

	res, err := s.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send SOAP request")
	}
	defer res.Body.Close()
	buf.Reset()
	if _, err := io.Copy(buf, res.Body); err != nil {
		return errors.Wrap(err, "failed to read SOAP body")
	}
	if res.StatusCode != http.StatusOK {
		return errors.Errorf("HTTP Status Code: %d, SOAP Fault: \n%s", res.StatusCode, buf.String())
	}

	if buf.Len() == 0 {
		return nil
	}
	respEnvelope := Envelope{}
	respEnvelope.Body = Body{Content: response}
	if header != nil {
		respEnvelope.Header = &Header{Content: header}
	}

	if err = xml.Unmarshal(buf.Bytes(), &respEnvelope); err != nil {
		return errors.Wrap(err, "failed to unmarshal response SOAP Envelope")
	}
	return nil
}
