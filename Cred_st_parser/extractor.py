import re
from fuzzywuzzy import fuzz
import pandas as pd
import streamlit as st
# import re
import unicodedata
def safe_extract(pattern, text):
    """Safely extract text using regex with or without capturing groups."""
    try:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            # Return first capturing group if available
            if match.lastindex:
                return match.group(1).strip()
            else:
                return match.group(0).strip()
    except Exception as e:
        st.write(f"⚠️ Regex error for pattern {pattern}: {e}")
    return None


def normalize_text(text):
    text = text.lower()
    text = re.sub(r'[\n\r]+', ' ', text)  # remove newlines
    text = re.sub(r'\s{2,}', ' ', text)   # collapse extra spaces
    text = re.sub(r'[^a-z0-9\s:/.-]', '', text)  # remove special chars except needed ones
    return text


def identify_issuer(text):
    """
    Robust issuer identification with priority-based matching
    """
    text_lower = text.lower()
    text_lower = re.sub(r'[\n\r\t]', ' ', text_lower)
    text_lower = re.sub(r'\s+', ' ', text_lower)
    text_lower = re.sub(r'(\b[a-z]\s)+', lambda m: ''.join(m.group(0).split()), text_lower)

    # Priority-based issuer patterns (order matters)
    issuer_patterns = [
        ("HDFC", [r'\bhdfc\s*bank\b', r'\bhdfc\b', r'\bh\s*d\s*f\s*c\b']),
        ("ICICI", [r'\bicici\s*bank\b', r'\bicici\b', r'\bi\s*c\s*i\s*c\s*i\b']),
        ("Axis", [r'\baxis\s*bank\b', r'\bflipkart\s*axis\b', r'\baxis\b']),
        ("Bank of America", [r'\bbank\s*of\s*america\b', r'\balaska\s*mileage\b', r'\bbofa\b', r'\bboa\b']),
        #("Citi", [r'\bcitibank\b', r'\bciti\s*bank\b', r'\bciti\b']),
        ("BDO", [r'\bbdo\s*unibank\b', r'\bbdo\s*bank\b', r'\bbdo\b'])
    ]

    st.write("🧾 Cleaned text sample (first 400 chars):")
    st.text(text_lower[:400])

    # Check for exact matches first
    for issuer, patterns in issuer_patterns:
        for pattern in patterns:
            if re.search(pattern, text_lower):
                st.write(f"✅ Exact match found: '{pattern}' -> {issuer}")
                return issuer

    # Fallback to fuzzy matching
    best_match = None
    highest_score = -1

    for issuer, patterns in issuer_patterns:
        for pattern in patterns:
            clean_pattern = pattern.replace(r'\b', '').replace(r'\s*', ' ')
            fuzzy_score = fuzz.partial_ratio(clean_pattern, text_lower)
            if fuzzy_score > highest_score:
                highest_score = fuzzy_score
                best_match = issuer

    if highest_score >= 60 and best_match:
        st.write(f"✅ Fuzzy match: {best_match} (score {highest_score})")
        return best_match

    st.write("❌ No reliable issuer match found")
    return "Unknown"


def extract_hdfc_data(text):
    """Extract data specific to HDFC statements - tuned for the provided image layout."""
    data = {}
    st.write("🔍 Extracting HDFC data...")
    text = re.sub(r'\s+', ' ', text)          # remove newlines and extra spaces
    text = text.replace(":", " : ")           # separate colons
    text = text.replace(">", " > ")           # separate arrows if OCR adds them
    text = text.replace("|", " ")             # remove OCR artifacts
    # --- Regex patterns tailored for HDFC statement layout ---
    patterns = {
        "Statement Date": [
            r"statement\s*date\s*[:\-]?\s*(\d{2}[\/\-]\d{2}[\/\-]\d{4})",
            r"date\s*of\s*statement\s*[:\-]?\s*(\d{2}[\/\-]\d{2}[\/\-]\d{4})",
        ],

        # e.g. "Payment Due Date 01/04/2023"
        "Payment Due Date": [
            r"payment\s*due\s*date\s*[:\-]?\s*(\d{2}[\/\-]\d{2}[\/\-]\d{4})",
            r"due\s*date\s*[:\-]?\s*(\d{2}[\/\-]\d{2}[\/\-]\d{4})",
        ],

        # e.g. "Total Dues 22,935.00" or "Total Amount Due : ₹22,935.00"
        "Total Amount Due": [
            r"total\s*(?:amount\s*)?dues?\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})",
            r"total\s*amount\s*due\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})",
        ],

        # e.g. "Minimum Amount Due 22,935.00"
        "Minimum Amount Due": [
            r"minimum\s*amount\s*due\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})",
            r"min(?:imum)?\s*due\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})",
        ],

        # e.g. "Card No: 4095 25XX XXXX 9348"
        "Card Last 4 Digits": [
            r"card\s*no[:\-]?\s*[xX*\s\d]+?(\d{4})\b",
            r"\b(\d{4})\b(?=\s*$)",  # last standalone 4 digits
        ],

        # e.g. "Credit Limit 30,000.00"
        "Credit Limit": [
            r"credit\s*limit\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})",
        ],

        # e.g. "Available Credit Limit 0.00"
        "Available Credit Limit": [
            r"available\s*credit\s*limit\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})",
        ],
    }

    # --- Safe extraction using helper ---
    for field, pattern_list in patterns.items():
        found = False
        for pattern in pattern_list:
            value = safe_extract(pattern, text)
            if value:
                data[field] = value
                st.write(f"✓ {field}: {value}")
                found = True
                break
        if not found:
            data[field] = "Not Found"
            st.write(f"✗ {field}: Not Found")

    return data


def extract_icici_data(text):
    text = normalize_text(text)
    data = {}
    patterns = {
        "issuer": [
            r"hdfc\s*bank",
            r"paytm\s*hdfc\s*bank",
            r"sbi\s*card",
            r"icici\s*bank",
            r"axis\s*bank",
            r"bdo\s*bank",
        ],
        "statement_period": [
            r"statement\s*period\s*:?[\s]*(\d{1,2}\s*[a-z]{3,9}\s*\d{4})\s*(?:to|-)\s*(\d{1,2}\s*[a-z]{3,9}\s*\d{4})",
            r"period\s*:?[\s]*(\d{1,2}\s*[a-z]{3,9}\s*\d{4}).*?to\s*(\d{1,2}\s*[a-z]{3,9}\s*\d{4})",
        ],
        "payment_due_date": [
            r"payment\s*due\s*date\s*:?[\s]*(\d{1,2}\s*[a-z]{3,9}\s*\d{4})",
            r"due\s*date\s*:?[\s]*(\d{1,2}\s*[a-z]{3,9}\s*\d{4})",
        ],
        "total_amount_due": [
            r"total\s*amount\s*due\s*:?[\s₹]*(\d+[.,]?\d*)",
            r"total\s*dues\s*:?[\s₹]*(\d+[.,]?\d*)",
        ],
        "minimum_amount_due": [
            r"minimum\s*amount\s*due\s*:?[\s₹]*(\d+[.,]?\d*)",
            r"min\s*amt\s*due\s*:?[\s₹]*(\d+[.,]?\d*)",
        ],
        "credit_limit": [
            r"credit\s*limit\s*:?[\s₹]*(\d+[.,]?\d*)",
            r"total\s*credit\s*limit\s*:?[\s₹]*(\d+[.,]?\d*)",
            r"available\s*credit\s*limit\s*:?[\s₹]*(\d+[.,]?\d*)",
        ],
        "available_credit_limit": [
            r"available\s*credit\s*limit\s*:?[\s₹]*(\d+[.,]?\d*)",
        ]
    }

    for field, pattern_list in patterns.items():
        found = False
        for pattern in pattern_list:
            value = safe_extract(pattern, text)
            if value:
                data[field] = value
                st.write(f"✓ {field}: {value}")
                found = True
                break
        if not found:
            data[field] = "Not Found"
            st.write(f"✗ {field}: Not Found")

    return data

def extract_axis_data(text):
    """Extract data specific to Axis statements - Based on Image 2"""
    data = {}
    
    st.write("🔍 Extracting Axis data...")
    
    # Axis/Flipkart uses format: 15/10/2021
    patterns = {
        "Statement Date": [
            r"statement\s*generation\s*date\s*[:\-]?\s*(\d{2}[\/\-]\d{2}[\/\-]\d{4})",
            r"(\d{2}[\/\-]\d{2}[\/\-]\d{4})\s*$",  # date at end of line
        ],
        "Payment Due Date": [
            r"payment\s*due\s*date\s*[:\-]?\s*(\d{2}[\/\-]\d{2}[\/\-]\d{4})",
            r"(\d{2}[\/\-]\d{2}[\/\-]\d{4})",
        ],
        "Billing Period": [
            r"(\d{2}[\/\-]\d{2}[\/\-]\d{4})\s*-\s*(\d{2}[\/\-]\d{2}[\/\-]\d{4})",
        ],
        "Total Amount Due": [
            r"total\s*payment\s*due\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})\s*(?:dr|cr)?",
            r"([0-9,]+\.\d{2})\s+dr",  # specific format in image
        ],
        "Minimum Amount Due": [
            r"minimum\s*payment\s*due\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})\s*(?:dr|cr)?",
            r"([0-9,]+\.\d{2})\s+dr",
        ],
        "Card Last 4 Digits": [
            r"credit\s*card\s*number\s*[:\-]?\s*[xX*\d]*?(\d{4})",
            r"(\d{4})\*+\d{4}",
        ],
        "Credit Limit": [
            r"credit\s*limit\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})",
            r"([0-9]{2,3},\d{3}\.\d{2})",
        ],
        "Available Credit": [
            r"available\s*credit\s*limit\s*[:\-]?\s*(?:rs\.?|₹)?\s*([0-9,]+\.?\d{0,2})",
        ],
    }
    
    for field, pattern_list in patterns.items():
        found = False
        for pattern in pattern_list:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                if field == "Billing Period" and len(match.groups()) > 1:
                    value = f"{match.group(1)} to {match.group(2)}"
                else:
                    value = match.group(1).strip()
                data[field] = value
                st.write(f"✓ {field}: {value}")
                found = True
                break
        if not found:
            data[field] = "Not Found"
            st.write(f"✗ {field}: Not Found")
    
    return data


def extract_boa_data(text):
    """Extract data specific to Bank of America statements - Based on Image 4"""
    data = {}
    
    st.write("🔍 Extracting Bank of America data...")
    
    # BOA uses format: 10/27/2020 and September 28 - October 27, 2020
    patterns = {
        "Statement Date": [
            r"statement\s*closing\s*date\s*[:\-]?\s*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})",
            r"(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})",
        ],
        "Billing Period": [
            r"(\w+\s+\d{1,2})\s*-\s*(\w+\s+\d{1,2},\s*\d{4})",
        ],
        "Payment Due Date": [
            r"payment\s*due\s*date\s*[:\-]?\s*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})",
            r"(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})",
        ],
        "Total Amount Due": [
            r"new\s*balance\s*total\s*[:\-]?\s*[-]?\$?\s*([0-9,]+\.?\d{0,2})",
            r"[-]?\$\s*([0-9,]+\.\d{2})",
        ],
        "Minimum Amount Due": [
            r"total\s*minimum\s*payment\s*due\s*[:\-]?\s*\$?\s*([0-9,]+\.?\d{0,2})",
            r"minimum\s*payment\s*[:\-]?\s*\$?\s*([0-9,]+\.?\d{0,2})",
        ],
        "Credit Limit": [
            r"total\s*credit\s*line\s*[:\-]?\s*\$?\s*([0-9,]+\.?\d{0,2})",
            r"\$\s*([0-9,]+\.\d{2})",
        ],
        "Available Credit": [
            r"total\s*credit\s*available\s*[:\-]?\s*\$?\s*([0-9,]+\.?\d{0,2})",
        ],
        "Previous Balance": [
            r"previous\s*balance\s*[:\-]?\s*[-]?\$?\s*([0-9,]+\.?\d{0,2})",
        ],
    }
    
    for field, pattern_list in patterns.items():
        found = False
        for pattern in pattern_list:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                if field == "Billing Period" and len(match.groups()) > 1:
                    value = f"{match.group(1)} - {match.group(2)}"
                else:
                    value = match.group(1).strip()
                data[field] = value
                st.write(f"✓ {field}: {value}")
                found = True
                break
        if not found:
            data[field] = "Not Found"
            st.write(f"✗ {field}: Not Found")
    
    return data


def extract_bdo_data(text):
    """Extract data specific to BDO statements - Based on Image 5"""
    data = {}
    
    st.write("🔍 Extracting BDO data...")
    
    # BDO uses format: March 2, 2023 and Mar 27, 2023
    patterns = {
        "Statement Date": [
            r"statement\s*date\s*[:\-]?\s*(\w+\s+\d{1,2},\s*\d{4})",
            r"(\w+\s+\d{1,2},\s*\d{4})",
        ],
        "Payment Due Date": [
            r"payment\s*due\s*date\s*[:\-]?\s*(\w+\s+\d{1,2},\s*\d{4})",
            r"(\w+\s+\d{1,2},\s*\d{4})",
        ],
        "Total Amount Due": [
            r"outstanding\s*balance\s*[:\-]?\s*(?:php|p|₱)?\s*([0-9,]+\.?\d{0,2})",
            r"p\s*([0-9,]+\.\d{2})",
        ],
        "Minimum Amount Due": [
            r"minimum\s*payment\s*[:\-]?\s*(?:php|p|₱)?\s*([0-9,]+\.?\d{0,2})",
            r"p\s*([0-9,]+\.\d{2})",
        ],
        "Card Number": [
            r"card\s*number\s*[:\-]?\s*(\d{4}-\d{4}-\d{4}-\d{4})",
            r"(\d{4}-\d{4}-\d{4}-\d{4})",
        ],
        "Credit Limit": [
            r"credit\s*limit\s*[:\-]?\s*(?:php|p|₱)?\s*([0-9,]+\.?\d{0,2})",
            r"p\s*([0-9,]+\.?\d{2})",
        ],
        "Interest Rate": [
            r"interest\s*rate\s*per\s*month\s*[:\-]?\s*([0-9.]+%)",
            r"(\d+\.\d+%)",
        ],
    }
    
    for field, pattern_list in patterns.items():
        found = False
        for pattern in pattern_list:
            value = safe_extract(pattern, text)
            if value:
                data[field] = value
                st.write(f"✓ {field}: {value}")
                found = True
                break
        if not found:
            data[field] = "Not Found"
            st.write(f"✗ {field}: Not Found")
    
    return data


def extract_data(text):
    """
    Main extraction function that routes to issuer-specific extractors
    """
    issuer = identify_issuer(text)
    
    # Show a sample of the text for debugging
    st.write("📝 Text sample for extraction (first 1000 chars):")
    st.text(text[:1000])
    
    # Route to appropriate extractor
    if issuer == "HDFC":
        extracted_data = extract_hdfc_data(text)
    elif issuer == "ICICI":
        extracted_data = extract_icici_data(text)
    elif issuer == "Axis":
        extracted_data = extract_axis_data(text)
    elif issuer == "Bank of America":
        extracted_data = extract_boa_data(text)
    elif issuer == "BDO":
        extracted_data = extract_bdo_data(text)
    else:
        # Fallback: try generic extraction
        st.warning("Using generic extraction patterns")
        extracted_data = extract_generic_data(text)
    
    # Add issuer to data
    extracted_data["Issuer"] = issuer
    
    # Reorder to put Issuer first
    data = {"Issuer": issuer}
    data.update(extracted_data)
    
    # Create DataFrame
    df = pd.DataFrame([data])
    
    return data, df


def extract_generic_data(text):
    """Fallback generic extraction when issuer is unknown"""
    data = {}
    
    st.write("🔍 Using generic extraction...")
    
    patterns = {
        "Statement Date": [
            r"statement\s*(?:date|generation\s*date)\s*[:\-]?\s*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})",
            r"(\w+\s+\d{1,2},?\s*\d{4})",
        ],
        "Payment Due Date": [
            r"payment\s*due\s*date\s*[:\-]?\s*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})",
            r"due\s*date\s*[:\-]?\s*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})",
        ],
        "Total Amount Due": [
            r"total\s*(?:amount\s*)?(?:payment\s*)?due\s*[:\-]?\s*(?:rs\.?|₹|php|p|₱|\$)?\s*([0-9,]+\.?\d{0,2})",
            r"(?:outstanding|new)\s*balance\s*[:\-]?\s*(?:rs\.?|₹|php|p|₱|\$)?\s*([0-9,]+\.?\d{0,2})",
        ],
        "Minimum Amount Due": [
            r"minimum\s*(?:amount\s*|payment\s*)?due\s*[:\-]?\s*(?:rs\.?|₹|php|p|₱|\$)?\s*([0-9,]+\.?\d{0,2})",
        ],
        "Credit Limit": [
            r"credit\s*limit\s*[:\-]?\s*(?:rs\.?|₹|php|p|₱|\$)?\s*([0-9,]+\.?\d{0,2})",
        ],
    }
    
    for field, pattern_list in patterns.items():
        found = False
        for pattern in pattern_list:
            value = safe_extract(pattern, text)
            if value:
                data[field] = value
                st.write(f"✓ {field}: {value}")
                found = True
                break
        if not found:
            data[field] = "Not Found"
            st.write(f"✗ {field}: Not Found")
    
    return data