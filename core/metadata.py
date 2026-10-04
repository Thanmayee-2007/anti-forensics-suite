from PIL import Image, ExifTags

class MetadataAuditor:
    KNOWN_EDITORS = ["photoshop", "gimp", "exiftool", "paint.net", "lightroom"]

    @classmethod
    def audit_exif(cls, image_path: str) -> dict:
        """
        Extracts EXIF parameters, identifies editing software traces, and checks tag consistency.
        """
        try:
            img = Image.open(image_path)
            raw_exif = img._getexif()
        except Exception:
            return {"status": "ERROR", "warnings": ["Failed to parse image structure."], "metadata": {}}

        if not raw_exif:
            return {
                "status": "STRIPPED",
                "warnings": ["EXIF metadata block is absent (Potential anti-forensic metadata wipe)."],
                "metadata": {}
            }

        parsed_exif = {}
        for tag_id, value in raw_exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            parsed_exif[tag_name] = str(value)

        warnings = []
        software_tag = parsed_exif.get("Software", "").lower()
        
        # Check software signatures
        for editor in cls.KNOWN_EDITORS:
            if editor in software_tag:
                warnings.append(f"EDITED: Contaminated by editing software ('{parsed_exif['Software']}').")
                break

        # Check camera hardware tags
        if "Make" not in parsed_exif and "Model" not in parsed_exif:
            warnings.append("INCONSISTENT: Camera hardware signatures missing despite present EXIF headers.")

        return {
            "status": "FLAGGED" if warnings else "CANONICAL",
            "warnings": warnings,
            "metadata": parsed_exif
        }