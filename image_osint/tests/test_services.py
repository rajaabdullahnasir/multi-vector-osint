import io

from django.test import SimpleTestCase
from PIL import Image

from image_osint.services.exif_extractor import ExifExtractor
from image_osint.services.file_validator import ImageFileValidator
from image_osint.services.perceptual_hash import PerceptualHashEngine


def _minimal_png() -> bytes:
    """Valid small PNG without EXIF (generated via Pillow for test reliability)."""
    buffer = io.BytesIO()
    Image.new("RGB", (8, 8), color=(40, 80, 120)).save(buffer, format="PNG")
    return buffer.getvalue()


class ImageFileValidatorTests(SimpleTestCase):
    def test_accepts_valid_png(self):
        data = _minimal_png()
        f = io.BytesIO(data)
        result = ImageFileValidator().validate(f, "test.png")
        self.assertTrue(result.ok)
        self.assertEqual(result.detected_format, "png")
        self.assertEqual(result.mime_type, "image/png")

    def test_rejects_empty_file(self):
        f = io.BytesIO(b"")
        result = ImageFileValidator().validate(f)
        self.assertFalse(result.ok)
        self.assertIn("empty", result.error.lower())

    def test_rejects_fake_extension(self):
        f = io.BytesIO(b"not an image at all")
        result = ImageFileValidator().validate(f, "photo.jpg")
        self.assertFalse(result.ok)


class PerceptualHashTests(SimpleTestCase):
    def test_same_image_same_hash(self):
        data = _minimal_png()
        engine = PerceptualHashEngine()
        h1 = engine.compute(data)
        h2 = engine.compute(data)
        self.assertEqual(h1["perceptual_hash_hex"], h2["perceptual_hash_hex"])
        self.assertEqual(len(h1["perceptual_hash_bits"]), 64)

    def test_hamming_distance_zero_for_identical(self):
        data = _minimal_png()
        h = PerceptualHashEngine().compute(data)["perceptual_hash_hex"]
        self.assertEqual(PerceptualHashEngine.hamming_distance(h, h), 0)


class ExifExtractorTests(SimpleTestCase):
    def test_gps_parsing_with_pillow_tag_ids(self):
        """GPS IFD keys are integers in Pillow, not string names."""
        from PIL import ExifTags

        name_to_id = {name: tag_id for tag_id, name in ExifTags.GPSTAGS.items()}
        gps_ifd = {
            name_to_id["GPSLatitudeRef"]: b"N",
            name_to_id["GPSLatitude"]: ((40, 1), (42, 1), (0, 1)),
            name_to_id["GPSLongitudeRef"]: b"W",
            name_to_id["GPSLongitude"]: ((74, 1), (0, 1), (0, 1)),
        }
        coords = ExifExtractor()._parse_gps(gps_ifd)
        self.assertIsNotNone(coords)
        self.assertAlmostEqual(coords.latitude, 40.7, places=1)
        self.assertAlmostEqual(coords.longitude, -74.0, places=1)
        self.assertIn("google.com/maps", coords.google_maps_url or "")

    def test_png_without_exif_warns(self):
        result = ExifExtractor().extract(_minimal_png())
        self.assertEqual(result.format, "png")
        self.assertEqual(result.width, 8)
        self.assertFalse(result.has_exif)
        self.assertTrue(result.warnings)
