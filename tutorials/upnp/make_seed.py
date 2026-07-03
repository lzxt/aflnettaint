import os


def main() -> None:
    out_dir = os.path.join("tutorials", "upnp", "in-upnp")
    os.makedirs(out_dir, exist_ok=True)

    # A minimal SOAP body (ASCII).
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        '<u:GetStatusInfo xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        "</u:GetStatusInfo>"
        "</s:Body>"
        "</s:Envelope>"
    )

    body_bytes = body.encode("ascii", errors="strict")
    content_length = len(body_bytes)

    # Keep Content-Length fixed width (10 digits) so AFLNet can rewrite it in-place.
    cl_field = f"{content_length:010d}"

    # Adjust Host / path to match your target control URL.
    req = (
        "POST /upnp/control/WANIPConn1 HTTP/1.1\r\n"
        "Host: 127.0.0.1:5000\r\n"
        'Content-Type: text/xml; charset="utf-8"\r\n'
        'SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#GetStatusInfo"\r\n'
        f"Content-Length: {cl_field}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("ascii", errors="strict")

    out_path = os.path.join(out_dir, "seed1.raw")
    with open(out_path, "wb") as f:
        f.write(req)
        f.write(body_bytes)

    print(f"[+] Wrote {out_path} (body={content_length} bytes, Content-Length={cl_field})")


if __name__ == "__main__":
    main()



