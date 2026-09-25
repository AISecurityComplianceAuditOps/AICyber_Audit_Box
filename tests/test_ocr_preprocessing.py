# -*- coding: utf-8 -*-
"""A screenshot has far fewer pixels per glyph than a scan.

    pytest tests/test_ocr_preprocessing.py -v

WHY THIS EXISTS

The VAPT proof of concept is usually a screenshot of a tool, and a screenshot is
pasted at screen resolution: the Burp capture that prompted this is 940x381,
with body text about eight pixels tall. A scanned A4 page arrives around 2500px
wide with text five times that size. The recogniser was being handed both and
doing much worse on the one the product depends on.

Measured on that capture, scored against its known text with a word-order
independent comparison: 53% as the pipeline shipped, 62% with the image inverted
and tripled. The difference is not cosmetic. At 940px the vulnerability class
"Stored XSS]" was read as "XSSI" and the host as "appxyz-corp-internal.com"; at
3x both come out right -- and the class name is what the finding's title, its
description, its remediation and its CIA impact are all derived from.

Inversion is the second half. Recognition models are trained overwhelmingly on
dark text over a light page, and a tool screenshot is the reverse. Only an image
whose mean luminance says it really is dark gets flipped, so a scan or a
light-themed UI is never touched.
"""
import numpy as np
import pytest

from src.core.parsers.doc_parsers import (
    _OCR_MAX_PIXELS, _OCR_MAX_UPSCALE, _OCR_TARGET_WIDTH,
    _preprocess_image_for_ocr,
)


def _img(w, h, value):
    return np.full((h, w, 3), value, dtype=np.uint8)


def test_opencv_imports():
    """Every check below goes through OpenCV, and the pre-processing hands back
    the raw image when it cannot import -- so without this, a missing system
    library (libxcb.so.1 on a bare Linux) reads as "not enlarged", "not
    inverted" rather than as the import error it is."""
    import cv2  # noqa: F401


def test_a_small_screenshot_is_enlarged():
    out = _preprocess_image_for_ocr(_img(940, 381, 30))
    assert out.shape[1] > 940, "a 940px screenshot was fed to OCR unchanged"
    assert out.shape[1] <= _OCR_TARGET_WIDTH + 1, out.shape


def test_the_aspect_ratio_is_kept():
    src = _img(940, 381, 30)
    out = _preprocess_image_for_ocr(src)
    assert abs((out.shape[1] / out.shape[0]) - (940 / 381)) < 0.02, out.shape


def test_a_page_that_is_already_large_is_left_alone():
    """A scan gains nothing and would cost the square of the factor."""
    out = _preprocess_image_for_ocr(_img(2550, 3300, 240))
    assert out.shape[1] == 2550 and out.shape[0] == 3300, out.shape


def test_upscaling_is_capped():
    """A tiny image must not be blown up without limit."""
    out = _preprocess_image_for_ocr(_img(200, 80, 30))
    assert out.shape[1] <= 200 * _OCR_MAX_UPSCALE + 1, out.shape


def test_the_result_stays_within_the_pixel_ceiling():
    """A long narrow capture must not exhaust memory when tripled."""
    out = _preprocess_image_for_ocr(_img(1200, 9000, 30))
    assert out.shape[0] * out.shape[1] <= _OCR_MAX_PIXELS * 1.05, out.shape


def test_a_dark_screenshot_is_inverted():
    dark = _img(940, 381, 20)
    out = _preprocess_image_for_ocr(dark)
    assert float(np.mean(out)) > 128, (
        "a dark-theme capture was not inverted, so every glyph is read against "
        "the grain of what the recogniser was trained on")


def test_a_light_page_is_not_inverted():
    """The guard is what keeps scans and light UIs untouched."""
    light = _img(2550, 3300, 235)
    out = _preprocess_image_for_ocr(light)
    assert float(np.mean(out)) > 128, "a light page was inverted"


def test_the_output_is_still_three_channel_uint8():
    """The reader and doctr both expect that shape."""
    out = _preprocess_image_for_ocr(_img(940, 381, 30))
    assert out.ndim == 3 and out.shape[2] == 3, out.shape
    assert out.dtype == np.uint8


@pytest.mark.parametrize("shape", [(381, 940), (381, 940, 4)])
def test_greyscale_and_rgba_inputs_are_handled(shape):
    src = np.full(shape, 30, dtype=np.uint8)
    out = _preprocess_image_for_ocr(src)
    assert out.ndim == 3 and out.shape[2] == 3


def test_a_failure_returns_the_original_rather_than_raising():
    """OCR of a broken image must not take the whole ingest down."""
    out = _preprocess_image_for_ocr("not an image")
    assert out == "not an image"
