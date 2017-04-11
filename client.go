package soap

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type RequestEnvelope struct {
	XMLName   xml.Name       `xml:"soap:Envelope"`
	XmlnsSoap string         `xml:"xmlns:soap,attr"`
	Header    *RequestHeader `xml:",omitempty"`
	Body      RequestBody
}

type RequestHeader struct {
	XMLName xml.Name    `xml:"soap:Header"`
	Content interface{} `xml:",omitempty"`
}

type RequestBody struct {
	XMLName xml.Name    `xml:"soap:Body"`
	Fault   *Fault      `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type ResponseEnvelope struct {
	XMLName xml.Name
	Header  *ResponseHeader `xml:",omitempty"`
	Body    ResponseBody
}

type ResponseHeader struct {
	XMLName xml.Name
	Content interface{} `xml:",omitempty"`
}

type ResponseBody struct {
	XMLName xml.Name
	Fault   *Fault      `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

// Response fault
type Fault struct {
	XMLName xml.Name
	Code    string `xml:"faultcode,omitempty"`
	String  string `xml:"faultstring,omitempty"`
	Actor   string `xml:"faultactor,omitempty"`
	Detail  string `xml:"detail,omitempty"`
}

func (f *Fault) Error() string {
	return f.String
}

// NewClient return SOAP client
func NewClient(url string, useTls bool, timeoutInSec time.Duration, userAgent string, header interface{}) *Client {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: useTls,
		},
		Dial: func(network, addr string) (net.Conn, error) {
			timeout := time.Duration(timeoutInSec * time.Second)
			return net.DialTimeout(network, addr, timeout)
		},
	}

	return &Client{
		httpClient:   http.Client{Transport: tr},
		url:          url,
		timeoutInSec: timeoutInSec,
		userAgent:    userAgent,
		header:       header,
	}
}

// Client SOAP client
type Client struct {
	httpClient   http.Client
	url          string
	timeoutInSec time.Duration
	userAgent    string
	header       interface{}
	debug        bool
}

// UnmarshalXML unmarshal SOAPHeader
func (h *ResponseHeader) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	h.XMLName = start.Name
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
func (b *ResponseBody) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}
	b.XMLName = start.Name
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
		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError(
					"Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Local == "Fault" {
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

func (s *Client) EnableDebugLog() {

	s.debug = true
}

func (s *Client) DisableDebugLog() {

	s.debug = false
}

func (s *Client) SendRaw(soapAction, contentType string, message io.Reader, response interface{}) error {

	if s.debug {
		messageBuffer, err := ioutil.ReadAll(message)
		if err != nil {
			return errors.Wrap(err, "failed to read message")
		}
		log.Println(string(messageBuffer))
		message = bytes.NewBuffer(messageBuffer)
	}

	req, err := http.NewRequest("POST", s.url, message)
	if err != nil {
		return errors.Wrap(err, "failed to create POST request")
	}

	if soapAction != "" {
		req.Header.Set("SOAPAction", soapAction)
		contentType += ";action=" + soapAction
	}
	if s.userAgent != "" {
		req.Header.Set("User-Agent", s.userAgent)
	}
	req.Header.Add("Content-Type", contentType)
	req.Close = true

	res, err := s.httpClient.Do(req)
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

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read SOAP body")
	}
	body := strings.TrimLeft(string(raw), " \r\n\t")
	if len(body) == 0 {
		return nil
	}

	if s.debug {
		log.Println(body)
	}

	if strings.HasPrefix(body, "--") {

		lines := strings.Split(body, "\r\n")
		if len(lines) == 0 {
			return errors.New("unknown response body format")
		}
		multipartReader := multipart.NewReader(bytes.NewReader(raw), strings.TrimLeft(lines[0], "-"))
		part, err := multipartReader.NextPart()
		if err != nil {
			return errors.Wrap(err, "error parsing multipart response body")
		}
		raw, err = ioutil.ReadAll(part)
		if err != nil {
			return errors.Wrap(err, "error reading multipart response body")
		}
	}

	if err = xml.Unmarshal(raw, response); err != nil {
		return errors.Wrap(err, "failed to unmarshal response SOAP Envelope")
	}
	return nil
}

func (s *Client) Send(soapAction string, message, response, responseHeader interface{}) error {

	buffer := new(bytes.Buffer)
	encoder := xml.NewEncoder(buffer)
	encoder.Indent("  ", "    ")
	if err := encoder.Encode(message); err != nil {
		return errors.Wrap(err, "failed to encode envelope")
	}
	if err := encoder.Flush(); err != nil {
		return errors.Wrap(err, "failed to flush encoder")
	}

	respEnvelope := ResponseEnvelope{}
	respEnvelope.Body = ResponseBody{Content: response}
	if responseHeader != nil {
		respEnvelope.Header = &ResponseHeader{Content: responseHeader}
	}
	return s.SendRaw(soapAction, "text/xml; charset=\"utf-8\"", buffer, &respEnvelope)
}

func (s *Client) Call(soapAction string, request, response, responseHeader interface{}) error {

	var envelope RequestEnvelope
	if s.header != nil {
		envelope = RequestEnvelope{
			XmlnsSoap: "http://www.w3.org/2003/05/soap-envelope",
			Header: &RequestHeader{
				Content: s.header,
			},
			Body: RequestBody{
				Content: request,
			},
		}
	} else {
		envelope = RequestEnvelope{
			Body: RequestBody{
				Content: request,
			},
		}
	}
	return s.Send(soapAction, envelope, response, responseHeader)
}
