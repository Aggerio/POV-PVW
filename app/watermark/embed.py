"""Embedder utilities.

Provides deterministic, seed-aware embedding for Variant A, legacy helpers
for the current FastAPI endpoints, and a lightweight demo image-watermarker
used in place of external services.
"""

import hashlib
import io
import secrets
from pathlib import Path
from typing import Dict, Optional, Tuple, Union
from urllib.request import urlopen

from PIL import Image


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DATA_DIR = _PROJECT_ROOT / "data"
_DEFAULT_DEMO_OUTPUT = _DATA_DIR / "watermarked_demo.png"
_RANDOM_IMAGE_ENDPOINT = "https://picsum.photos/seed/{seed}/{width}/{height}"


def _download_image(url: str) -> Image.Image:
    """Download an image from ``url`` and return it as an RGBA Pillow Image."""

    with urlopen(url, timeout=10) as response:  # nosec B310 - demo helper
        status = getattr(response, "status", response.getcode())
        if status != 200:
            raise RuntimeError(f"Failed to download image ({status}): {url}")
        raw = response.read()

    image = Image.open(io.BytesIO(raw))
    return image.convert("RGBA")


def _prepare_watermark(
    watermark: Image.Image,
    base_size: Tuple[int, int],
    scale: float,
    opacity: float,
) -> Image.Image:
    """Resize and fade a watermark image relative to a base image size."""

    target_width = max(1, int(base_size[0] * scale))
    ratio = target_width / watermark.width
    target_height = max(1, int(watermark.height * ratio))
    resized = watermark.resize(
        (target_width, target_height),
        Image.Resampling.LANCZOS,
    )
    if resized.mode != "RGBA":
        resized = resized.convert("RGBA")

    alpha = resized.getchannel("A") if "A" in resized.getbands() else Image.new("L", resized.size, 255)
    faded_alpha = alpha.point(lambda px: int(px * opacity))
    resized.putalpha(faded_alpha)
    return resized


def _overlay_watermark(
    base: Image.Image,
    watermark: Image.Image,
    margin_ratio: float,
) -> Image.Image:
    """Overlay watermark on the base image using the given margin ratio."""

    margin = max(5, int(min(base.size) * margin_ratio))
    position = (
        max(0, base.width - watermark.width - margin),
        max(0, base.height - watermark.height - margin),
    )
    composed = base.copy()
    composed.paste(watermark, position, watermark)
    return composed


def embed_demo_image(
    output_path: Optional[Union[str, Path]] = None,
    *,
    base_resolution: Tuple[int, int] = (1280, 720),
    watermark_resolution: Tuple[int, int] = (512, 512),
    watermark_scale: float = 0.35,
    opacity: float = 0.35,
    margin_ratio: float = 0.04,
) -> Dict[str, str]:
    """Generate a demo watermarked image using two random internet images.

    Downloads a random base image and a random watermark image from Picsum,
    overlays the watermark with partial transparency, and saves the output to
    ``output_path`` (default: ``data/watermarked_demo.png``).

    Returns a mapping containing the source URLs and the output path.
    """

    base_seed = secrets.token_hex(4)
    watermark_seed = secrets.token_hex(4)
    base_url = _RANDOM_IMAGE_ENDPOINT.format(
        seed=base_seed, width=base_resolution[0], height=base_resolution[1]
    )
    watermark_url = _RANDOM_IMAGE_ENDPOINT.format(
        seed=watermark_seed,
        width=watermark_resolution[0],
        height=watermark_resolution[1],
    )

    base_image = _download_image(base_url).resize(
        base_resolution, Image.Resampling.LANCZOS
    )
    watermark_image = _download_image(watermark_url)

    prepared_watermark = _prepare_watermark(
        watermark_image, base_resolution, watermark_scale, opacity
    )
    composed = _overlay_watermark(base_image, prepared_watermark, margin_ratio)

    if output_path is None:
        output = _DEFAULT_DEMO_OUTPUT
    else:
        output = Path(output_path)

    output.parent.mkdir(parents=True, exist_ok=True)
    composed.convert("RGB").save(output, format="PNG")

    return {
        "base_url": base_url,
        "watermark_url": watermark_url,
        "output_path": str(output),
    }


def _tag_from_key(key: bytes) -> str:
    """Derive a short, deterministic tag from the seed/key."""
    return hashlib.sha256(key).hexdigest()[:16]


def embed_with_key(text: str, key: bytes) -> Tuple[str, str]:
    """Embed using a deterministic key.

    Returns: (watermarked_text, tag_hex)
    """
    tag = _tag_from_key(key)
    zwsp = "\u200b"
    watermarked = f"{text}{zwsp}[wm:{tag}]"
    return watermarked, tag


# --- Backward-compatible function (used by current endpoints) ---
def embed_text(text: str, server_salt: bytes) -> Tuple[str, str, str]:
    """Legacy embed: generate a random seed and compute a commitment externally.

    Retained for compatibility until /issue is refactored to pass a derived key.
    Returns: (watermarked, commitment, seed_hex)
    Note: commitment computed here as sha256(server_salt + seed) for legacy flow.
    """
    seed = secrets.token_bytes(16)
    tag = _tag_from_key(seed)
    zwsp = "\u200b"
    watermarked = f"{text}{zwsp}[wm:{tag}]"
    # legacy commitment scheme (server_salt prefixed)
    commitment = hashlib.sha256(server_salt + seed).hexdigest()
    return watermarked, commitment, seed.hex()
