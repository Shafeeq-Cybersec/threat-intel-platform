import re
import logging
import cv2
import numpy as np
from services import risk_aggregator

log = logging.getLogger(__name__)
_detector = cv2.QRCodeDetector()
_URL_RE = re.compile(r"^[\w.-]+\.[a-z]{2,}(?:[/:?].*)?$", re.I)


def decode_payloads(image_bytes: bytes) -> list:
    """Returns every QR payload found in the image (handles multiple codes)."""
    arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("unreadable image")
    ok, decoded, _, _ = _detector.detectAndDecodeMulti(img)
    payloads = [d for d in decoded if d] if ok else []
    if not payloads:  # fall back to single-code detector
        single, _, _ = _detector.detectAndDecode(img)
        if single:
            payloads = [single]
    return payloads


def _looks_like_url(s: str) -> bool:
    s = s.strip()
    return s.lower().startswith(("http://", "https://")) or bool(_URL_RE.match(s))


def analyze(image_bytes: bytes) -> dict:
    """Decodes a QR image and pipes the embedded URL through the Phase 1 pipeline."""
    try:
        payloads = decode_payloads(image_bytes)
    except Exception as e:
        log.warning(f"[qr] decode failed: {e}")
        return {"error": f"could not read image: {e}"}

    if not payloads:
        return {"error": "no QR code found in image"}

    url = next((p for p in payloads if _looks_like_url(p)), None)
    if not url:
        return {"error": "QR code did not contain a URL", "decoded": payloads}

    normalized = url if url.lower().startswith(("http://", "https://")) else "http://" + url
    result = risk_aggregator.analyze_url(normalized)
    result["decoded_url"] = normalized
    result["all_payloads"] = payloads
    return result
