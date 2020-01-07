package main

func isChannelServer(port uint16) bool {
	return ((port >= 53410 && port <= 53420) || // TW channel server ports
		(port >= 54000 && port <= 54020)) // JP channel server ports
}

func isEntranceServer(port uint16) bool {
	return port == 53310
}

func isSignServer(port uint16) bool {
	return port == 53312
}

func isNullInitedServer(port uint16) bool {
	return isEntranceServer(port) || isSignServer(port)
}

func isMhfServer(port uint16) bool {
	return isEntranceServer(port) || isSignServer(port) || isChannelServer(port)
}
