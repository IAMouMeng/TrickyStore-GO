/*
Author: MouMeng
Mail: iamoumeng@aliyun.com
Date: 2026/4/21 21:36:40
*/

package listener

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"keystore_service/internal/alias"
	"keystore_service/internal/attestation"
	"keystore_service/internal/cert"
	"log"
	"net"
	"os"
)

type Listener struct{}

func New() *Listener {
	return &Listener{}
}

func (l *Listener) readRequest(r io.Reader) (*Request, error) {
	var totalLen uint32

	if err := binary.Read(r, binary.LittleEndian, &totalLen); err != nil {
		return nil, err
	}

	buf := make([]byte, totalLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	offset := 0

	reqType := buf[offset]
	offset += 1

	uidLen := binary.LittleEndian.Uint32(buf[offset:])
	offset += 4

	if uidLen != 4 {
		return nil, fmt.Errorf("invalid uid_len: %d", uidLen)
	}

	uid := binary.LittleEndian.Uint32(buf[offset:])
	offset += 4

	aliasLen := binary.LittleEndian.Uint32(buf[offset:])
	offset += 4

	if int(aliasLen) > len(buf)-offset {
		return nil, fmt.Errorf("invalid alias_len")
	}

	aliasName := string(buf[offset : offset+int(aliasLen)])
	offset += int(aliasLen)

	dataLen := binary.LittleEndian.Uint32(buf[offset:])
	offset += 4

	if int(dataLen) > len(buf)-offset {
		return nil, fmt.Errorf("invalid data_len")
	}

	data := buf[offset : offset+int(dataLen)]

	return &Request{
		Type:  reqType,
		UID:   uid,
		Alias: aliasName,
		Data:  data,
	}, nil
}

func (l *Listener) writeResponse(w io.Writer, status uint8, data []byte) error {
	var body bytes.Buffer

	body.WriteByte(status)

	if err := binary.Write(&body, binary.LittleEndian, uint32(len(data))); err != nil {
		return err
	}

	if _, err := body.Write(data); err != nil {
		return err
	}

	totalLen := uint32(body.Len())
	if err := binary.Write(w, binary.LittleEndian, totalLen); err != nil {
		return err
	}

	_, err := w.Write(body.Bytes())
	return err
}

func (l *Listener) handleConn(conn net.Conn) {
	defer conn.Close()

	for {
		req, err := l.readRequest(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("error reading request: %v", err)
			}
			return
		}

		log.Printf("recv: type: %d alias:%s  uid:%d data_len: %d\n", req.Type, req.Alias, req.UID, len(req.Data))

		//if req.Alias == "Wuying_cert" {
		//	l.writeResponse(conn, 0, nil)
		//}

		switch req.Type {
		case 0: // genKeyPair cert leaf request
			data, err := cert.HackLeafCert(req.Data)
			if err != nil {
				log.Println("cert.ParseLeafCert:", err)
				l.writeResponse(conn, 0, nil)
				return
			}
			alias.Store.StoreLeaf(req.UID, req.Alias, data)
			l.writeResponse(conn, 1, data)
		case 1: // genKeyPair chain request
			data, err := cert.HackCertChain(req.Data)
			if err != nil {
				log.Println("cert.ParseChain:", err)
				l.writeResponse(conn, 0, nil)
				return
			}
			alias.Store.StoreKeychain(req.UID, req.Alias, data)
			l.writeResponse(conn, 1, data)
		case 2: // getKeyEntry cert leaf request
			parseCert, _err := x509.ParseCertificate(req.Data)
			if _err != nil {
				fmt.Println("x509.ParseCertificate:", _err)
				l.writeResponse(conn, 0, nil)
				return
			}

			if _, _err = attestation.ParseCertificate(parseCert); _err != nil {
				fmt.Println(parseCert.Subject)
				l.writeResponse(conn, 0, nil)
				return
			}

			if data, ok := alias.Store.GetLeaf(req.UID, req.Alias); ok {
				l.writeResponse(conn, 1, data)
				return
			}
			l.writeResponse(conn, 0, nil)
		case 3: // getKeyEntry chain request
			if data, ok := alias.Store.GetKeychain(req.UID, req.Alias); ok {
				l.writeResponse(conn, 1, data)
				return
			}
			l.writeResponse(conn, 0, nil)
		default:
			if err = l.writeResponse(conn, 0, nil); err != nil {
				return
			}
		}

	}
}

func (l *Listener) Run() {
	if _, err := os.Stat(listenAddr); err == nil {
		os.Remove(listenAddr)
	}

	listener, err := net.Listen("unix", listenAddr)
	if err != nil {
		panic(err)
	}

	defer listener.Close()

	os.Chmod(listenAddr, 0777)

	for {
		conn, _err := listener.Accept()
		if _err != nil {
			continue
		}

		go l.handleConn(conn)
	}
}
