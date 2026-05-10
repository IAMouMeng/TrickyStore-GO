/*
Author: MouMeng
Mail: iamoumeng@aliyun.com
Date: 2026/4/21 21:40:32
*/

package listener

const listenAddr = "/dev/socket/keybox"

type Request struct {
	Type  uint8
	UID   uint32
	Alias string
	Data  []byte
}
