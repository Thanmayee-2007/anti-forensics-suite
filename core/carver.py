class FileCarver:
    MAGIC_SIGNATURES = {
        b"PK\x03\x04": "ZIP Archive / OpenXML Document",
        b"MZ": "Windows PE Executable",
        b"%PDF": "PDF Document",
        b"Rar!": "RAR Compressed Archive",
        b"\x7fELF": "Linux ELF Executable"
    }

    @classmethod
    def scan_polyglot(cls, file_bytes: bytes, filename: str) -> dict:
        """
        Scans for trailing overlay data beyond official End-Of-Image (EOI) format boundaries.
        """
        extension = filename.split(".")[-1].lower() if "." in filename else ""
        results = {
            "is_polyglot": False,
            "eoi_offset": -1,
            "extra_bytes": 0,
            "carved_payloads": []
        }

        eoi_offset = -1
        
        if extension in ["jpg", "jpeg"]:
            pos = file_bytes.rfind(b"\xff\xd9")
            if pos != -1:
                eoi_offset = pos + 2
        elif extension == "png":
            pos = file_bytes.rfind(b"IEND\xaeB`\x82")
            if pos != -1:
                eoi_offset = pos + 8

        if eoi_offset != -1 and eoi_offset < len(file_bytes):
            overlay_data = file_bytes[eoi_offset:]
            results["is_polyglot"] = True
            results["eoi_offset"] = eoi_offset
            results["extra_bytes"] = len(overlay_data)

            for sig, payload_type in cls.MAGIC_SIGNATURES.items():
                sig_pos = overlay_data.find(sig)
                if sig_pos != -1:
                    results["carved_payloads"].append({
                        "type": payload_type,
                        "absolute_offset": eoi_offset + sig_pos,
                        "size_bytes": len(overlay_data) - sig_pos
                    })

        return results