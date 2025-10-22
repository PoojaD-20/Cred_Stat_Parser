import io
import tempfile
from PyPDF2 import PdfReader
from pdf2image import convert_from_path
import pytesseract
from PIL import Image
import os

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

def extract_text_from_pdf(uploaded_file):
    text = ""

    # Save Streamlit UploadedFile to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_file_path = tmp_file.name

    try:
        reader = PdfReader(tmp_file_path)
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text
    except Exception as e:
        print("PyPDF2 text extraction error:", e)

    # If no text found, try OCR
    if not text.strip():
        print("No text found using PyPDF2 — running OCR...")
        try:
            images = convert_from_path(tmp_file_path)
            ocr_text = ""
            for i, img in enumerate(images):
                ocr_page_text = pytesseract.image_to_string(img)
                ocr_text += f"\n--- Page {i+1} ---\n" + ocr_page_text
            text = ocr_text
        except Exception as e:
            print("OCR extraction failed:", e)

    # Clean up temporary file
    os.remove(tmp_file_path)

    return text