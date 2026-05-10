/*
Author: MouMeng
Mail: iamoumeng@aliyun.com
Date: 2026-04-21 21:26:30
*/

package main

import "keystore_service/internal/listener"

func main() {
	server := listener.New()
	server.Run()
}
