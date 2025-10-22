import streamlit as st
import json
from utils import extract_text_from_pdf
from extractor import extract_data
import re
import unicodedata

def normalize_text(text):
    """
    Clean and normalize OCR or PDF-extracted text.
    - Converts to lowercase
    - Removes extra spaces and line breaks
    - Fixes common OCR mistakes (like 0↔O, 1↔I)
    - Removes non-printable characters
    """
    # Normalize Unicode (remove weird accents, hidden chars)
    text = unicodedata.normalize("NFKD", text)
    
    # Convert to lowercase for consistent regex matching
    text = text.lower()
    
    # Replace common OCR mix-ups
    replacements = {
        '₹': 'rs',
        'srs': 'rs',
        'due datee': 'due date',
        'dues date': 'due date',
        'daté': 'date',
        'o0': '00',
        '0o': '00',
        'ii': '11',
        'l': '1',   # sometimes l -> 1 in OCR
        'hdf0': 'hdfc',
        'hdf o': 'hdfc',
        'axisb ank': 'axis bank',
        'icic i': 'icici'
    }
    for k, v in replacements.items():
        text = text.replace(k, v)

    # Remove excessive whitespace and line breaks
    text = re.sub(r'\s+', ' ', text)

    # Remove any unwanted special characters (optional)
    text = re.sub(r'[^\x00-\x7F]+', ' ', text)
    
    # Trim extra spaces
    text = text.strip()
    
    return text

st.set_page_config(page_title="Credit Card Parser", page_icon="💳", layout="centered")

st.title("💳 Credit Card Statement Parser")

uploaded_file = st.file_uploader("Upload your Credit Card Statement (PDF) 📃", type=["pdf"])

if uploaded_file:
    st.info("Extracting text and identifying issuer...")
    text = extract_text_from_pdf(uploaded_file)

    #st.write("🔍 Extracted Text Preview:")
    #st.text(text[:1000])

    detected = [word for word in ["hdfc", "icici", "axis", "bank of america", "boa"] if word in text.lower()]
    st.write("Detected keywords in text:", detected)

    text_clean = normalize_text(text)

    st.text(text_clean[:800])  # Preview normalized text
    parsed, df = extract_data(text_clean)

    if parsed["Issuer"] == "Unknown":
        st.error("❌ Could not identify the card issuer. Please upload a supported statement.")
    else:
        st.success(f"✅ Extracted data from {parsed['Issuer']}")
        st.subheader("📄 Extracted Information")
        st.json(parsed)
        st.dataframe(df)

        st.download_button(
            label="⬇️ Download Extracted Data (JSON)",
            data=json.dumps(parsed, indent=2),
            file_name=f"{parsed['Issuer']}_statement.json",
            mime="application/json"
        )

