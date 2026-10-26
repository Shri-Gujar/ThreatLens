def detect_threats(packets, known_ips=None):
    alerts = []

    connection_attempts = {}
    scanned_ports = {}

    unusual_ports = {4444, 5555, 6667, 31337}

    if known_ips is None:
        known_ips = set()

    for packet in packets:
        if packet.haslayer("IP"):
            source_ip = packet["IP"].src
            destination_ip = packet["IP"].dst

            if packet.haslayer("TCP"):
                destination_port = packet["TCP"].dport
                flags = packet["TCP"].flags

                # Detect repeated TCP connection attempts
                if flags & 0x02 and not flags & 0x10:
                    key = (source_ip, destination_ip, destination_port)

                    connection_attempts[key] = (
                        connection_attempts.get(key, 0) + 1
                    )

                    # Track different ports targeted by each source
                    scan_key = (source_ip, destination_ip)

                    if scan_key not in scanned_ports:
                        scanned_ports[scan_key] = set()

                    scanned_ports[scan_key].add(destination_port)

                # Detect traffic to unusual ports
                if destination_port in unusual_ports:
                    alerts.append({
                        "Type": "Unusual Destination Port",
                        "Source IP": source_ip,
                        "Destination IP": destination_ip,
                        "Port": destination_port,
                        "Evidence": (
                            f"Traffic observed to port {destination_port}"
                        )
                    })

    # Generate repeated connection alerts
    for connection, count in connection_attempts.items():
        if count >= 10:
            source_ip, destination_ip, port = connection

            alerts.append({
                "Type": "Repeated Connection Attempts",
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Port": port,
                "Evidence": (
                    f"{count} TCP connection attempts observed"
                )
            })

    # Detect possible port scanning
    for connection, ports in scanned_ports.items():
        if len(ports) >= 5:
            source_ip, destination_ip = connection

            alerts.append({
                "Type": "Possible Port Scan",
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Port": None,
                "Evidence": (
                    f"Connection attempts targeted "
                    f"{len(ports)} different destination ports"
                )
            })

    return alerts