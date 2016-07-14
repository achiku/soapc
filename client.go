package soap

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

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
func NewClient(url string, tls bool, header interface{}) *Client {
	return &Client{
		url:    url,
		tls:    tls,
		header: header,
	}
}

// Client SOAP client
type Client struct {
	url       string
	tls       bool
	userAgent string
	header    interface{}
}

func dialTimeout(network, addr string) (net.Conn, error) {
	timeout := time.Duration(30 * time.Second)
	return net.DialTimeout(network, addr, timeout)
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

// Call SOAP client API call
func (s *Client) Call(soapAction string, request, response, header interface{}) error {
	var envelope Envelope
	if s.header != nil {
		envelope = Envelope{
			Header: &Header{
				Content: s.header,
			},
			Body: Body{
				Content: request,
			},
		}
	} else {
		envelope = Envelope{
			Body: Body{
				Content: request,
			},
		}
	}
	buffer := new(bytes.Buffer)
	encoder := xml.NewEncoder(buffer)
	encoder.Indent("  ", "    ")
	if err := encoder.Encode(envelope); err != nil {
		return errors.Wrap(err, "failed to encode envelope")
	}
	if err := encoder.Flush(); err != nil {
		return errors.Wrap(err, "failed to flush encoder")
	}

	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return errors.Wrap(err, "failed to create POST request")
	}
	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", soapAction)
	req.Header.Set("User-Agent", s.userAgent)
	req.Close = true

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.tls,
		},
		Dial: dialTimeout,
	}

	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send SOAP request")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		soapFault, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.Wrap(err, "failed to read SOAP fault response body")
		}
		msg := fmt.Sprintf("HTTP Status Code: %d, SOAP Fault: \n%s", res.StatusCode, string(soapFault))
		return errors.New(msg)
	}

	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read SOAP body")
	}
	if len(rawbody) == 0 {
		return nil
	}
	respEnvelope := Envelope{}
	respEnvelope.Body = Body{Content: response}
	if header != nil {
		respEnvelope.Header = &Header{Content: header}
	}

	if err = xml.Unmarshal(rawbody, &respEnvelope); err != nil {
		return errors.Wrap(err, "failed to unmarshal response SOAP Envelope")
	}
	return nil
}
