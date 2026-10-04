import os
import tempfile
import streamlit as st
import numpy as np
from PIL import Image

from core.stego import StegoAnalyzer
from core.timestomp import TimestompDetector
from core.metadata import MetadataAuditor
from core.carver import FileCarver

st.set_page_config(page_title="Anti-Forensics Suite", layout="wide")

st.title("🛡️ Anti-Forensics & Steganography Detection Suite")
st.caption("Digital Media Forensics | File Integrity Verification | Polyglot Auditing")

uploaded_file = st.file_uploader("Upload Evidence File", type=["jpg", "jpeg", "png", "bmp"])

if uploaded_file is not None:
    file_bytes = uploaded_file.read()
    image = Image.open(uploaded_file).convert("RGB")
    image_np = np.array(image)

    # Save temp file for timestamp operations
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{uploaded_file.name.split('.')[-1]}") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    tab1, tab2, tab3, tab4 = st.tabs([
        "🔬 Steganography Analysis", 
        "⏱️ Timestomping Audit", 
        "🏷️ Metadata Integrity", 
        "📦 File Carver & Polyglot"
    ])

    # Module 1: Steganography
    with tab1:
        st.subheader("LSB Visual Attack & Statistical Steganalysis")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.image(image, caption="Original Image", use_container_width=True)
        with col2:
            channel = st.selectbox("RGB Channel", [0, 1, 2], format_func=lambda x: ["Red", "Green", "Blue"][x])
            lsb_img = StegoAnalyzer.lsb_visual_attack(image_np, channel=channel)
            st.image(lsb_img, caption=f"LSB Bit-Plane (Channel {channel})", use_container_width=True)
        with col3:
            heatmap = StegoAnalyzer.generate_variance_heatmap(image_np)
            st.image(heatmap, caption="Pixel Variance Entropy Heatmap", use_container_width=True)

        st.markdown("---")
        chi2_stat, p_val, verdict = StegoAnalyzer.chi_square_analysis(image_np)
        st.metric("Chi-Square Statistic (χ²)", f"{chi2_stat:.2f}")
        st.metric("Statistical Probability (P-Value)", f"{p_val:.4f}")
        
        if "HIGH CONFIDENCE" in verdict:
            st.error(f"Verdict: {verdict}")
        elif "SUSPICIOUS" in verdict:
            st.warning(f"Verdict: {verdict}")
        else:
            st.success(f"Verdict: {verdict}")

    # Module 2: Timestomping
    with tab2:
        st.subheader("NTFS File System Timestamp Verification")
        ts_data = TimestompDetector.analyze_timestamps(tmp_path)
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Creation Time ($STD_INFO)", ts_data["created"])
        col2.metric("Modification Time", ts_data["modified"])
        col3.metric("Last Access Time", ts_data["accessed"])

        if ts_data["anomalies"]:
            for alert in ts_data["anomalies"]:
                st.error(alert)
        else:
            st.success("No timestamp anomalies detected.")

    # Module 3: EXIF Metadata
    with tab3:
        st.subheader("EXIF Parameter Audit")
        exif_results = MetadataAuditor.audit_exif(tmp_path)
        
        st.write(f"**Integrity Status:** `{exif_results['status']}`")
        if exif_results["warnings"]:
            for w in exif_results["warnings"]:
                st.warning(w)
                
        with st.expander("Raw EXIF Tag Dump"):
            st.json(exif_results["metadata"])

    # Module 4: Polyglot Carver
    with tab4:
        st.subheader("Magic Byte Audit & Appended Overlay Carver")
        poly_results = FileCarver.scan_polyglot(file_bytes, uploaded_file.name)
        
        if poly_results["is_polyglot"]:
            st.error(f"Polyglot Alert: Found {poly_results['extra_bytes']} bytes past End-Of-Image boundary!")
            st.write(f"**EOI Marker Offset:** `Byte {poly_results['eoi_offset']}`")
            
            if poly_results["carved_payloads"]:
                st.subheader("Carved Payload Signatures:")
                for payload in poly_results["carved_payloads"]:
                    st.write(f"- **Type:** `{payload['type']}` at Offset `{payload['absolute_offset']}` ({payload['size_bytes']} bytes)")
        else:
            st.success("Clean File Structure: End-Of-Image marker aligns with file boundary.")

    os.remove(tmp_path)