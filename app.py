import streamlit as st
import zipfile
import xml.etree.ElementTree as ET
import os
import fitz  # PyMuPDF
from docx import Document
import tempfile
from PIL import Image
import io
import re
from datetime import datetime


def analyze_pdf(file_bytes):
    metadata = {}
    with fitz.open(stream=file_bytes, filetype="pdf") as pdf:
        metadata['basic'] = pdf.metadata

        # Extract full document content
        full_text = ""
        metadata['content'] = {
            'annotations': {},
            'links': {},
            'forms': {}
        }

        for page_num in range(len(pdf)):
            page = pdf[page_num]

            # Get text for analysis
            full_text += page.get_text()

            # Get annotations
            annotations = page.annots()
            if annotations:
                metadata['content']['annotations'][f'page_{page_num+1}'] = [
                    {
                        'type': annot.type[1],
                        'content': annot.info.get('content', ''),
                        'modified': annot.info.get('modified', ''),
                        'subject': annot.info.get('subject', '')
                    } for annot in annotations
                ]

            # Get links
            links = page.get_links()
            if links:
                metadata['content']['links'][f'page_{page_num+1}'] = [
                    {
                        'type': link.get('type', ''),
                        'uri': link.get('uri', ''),
                        'destination': link.get('destination', '')
                    } for link in links
                ]

            # Get form fields
            widgets = page.widgets()
            if widgets:
                metadata['content']['forms'][f'page_{page_num+1}'] = [
                    {
                        'field_type': widget.field_type,
                        'field_name': widget.field_name,
                        'value': widget.field_value,
                    } for widget in widgets
                ]

        # Extract images and their metadata
        metadata['images'] = {}
        for page_num in range(len(pdf)):
            page = pdf[page_num]
            images = page.get_images()

            for img_index, img in enumerate(images):
                xref = img[0]
                base_image = pdf.extract_image(xref)
                if base_image:
                    image_bytes = base_image["image"]
                    metadata['images'][f'page_{page_num}_img_{img_index}'] = get_image_metadata(
                        image_bytes)

        # Analyze all text for sensitive data
        metadata['sensitive_data'] = find_sensitive_patterns(full_text)

    return metadata


def analyze_docx(file_bytes):
    metadata = {}

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        # Get core document properties
        doc = Document(tmp_path)

        # Get ZIP info for detailed metadata
        with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
            metadata['file_metadata'] = {
                'MIME_Type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'Application': doc.core_properties.identifier or '',
                'Doc_Security': 'None',  # Default unless otherwise specified
                'Create_Date': str(doc.core_properties.created) if doc.core_properties.created else '',
                'Creator': doc.core_properties.author or '',
                'Last_Modified_By': doc.core_properties.last_modified_by or '',
                'Modify_Date': str(doc.core_properties.modified) if doc.core_properties.modified else '',
                'Created': str(doc.core_properties.created) if doc.core_properties.created else '',
                'LastSaved': str(doc.core_properties.modified) if doc.core_properties.modified else '',
            }

            # Try to get additional metadata from app.xml
            if 'docProps/app.xml' in zip_ref.namelist():
                with zip_ref.open('docProps/app.xml') as app_xml:
                    tree = ET.parse(app_xml)
                    root = tree.getroot()

                    # Extract all properties from app.xml
                    for elem in root:
                        tag = elem.tag.split('}')[-1]
                        if elem.text and tag not in ['Template', 'Pages', 'Words', 'Characters', 'CharactersWithSpaces']:
                            metadata['file_metadata'][tag] = elem.text

        # Analyze ZIP contents
        with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
            metadata['zip_contents'] = {}

            # List all files in the ZIP
            all_files = zip_ref.namelist()
            metadata['zip_contents']['files'] = all_files

            # Get document statistics
            metadata['statistics'] = {
                'total_files': len(all_files),
                'media_files': len([f for f in all_files if 'media/' in f]),
                'embedded_files': len([f for f in all_files if 'embeddings/' in f]),
                'custom_xml': len([f for f in all_files if 'customXml/' in f])
            }

            # Improved XML text extraction
            all_text = []
            for xml_file in [f for f in all_files if f.endswith('.xml')]:
                try:
                    with zip_ref.open(xml_file) as f:
                        content = f.read().decode('utf-8')
                        # Remove XML tags but keep content
                        text_content = re.sub(r'<[^>]+>', ' ', content)
                        # Clean up whitespace
                        text_content = re.sub(
                            r'\s+', ' ', text_content).strip()
                        all_text.append(text_content)
                except Exception as e:
                    continue

            # Get visible document content
            visible_text = '\n'.join([
                para.text for para in doc.paragraphs if para.text.strip()
            ])
            all_text.append(visible_text)

            # Tables content
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text.strip():
                            all_text.append(cell.text)

            # Analyze all text content together
            full_text = ' '.join(all_text)
            # Clean up the text to help with pattern matching
            full_text = re.sub(r'\s+', ' ', full_text)
            metadata['sensitive_data'] = find_sensitive_patterns(full_text)

            # Extract and analyze embedded images
            metadata['embedded_images'] = {}
            for file in all_files:
                if any(file.startswith(prefix) for prefix in ['word/media/', 'word/embeddings/']):
                    try:
                        with zip_ref.open(file) as img_file:
                            img_bytes = img_file.read()
                            metadata['embedded_images'][file] = get_image_metadata(
                                img_bytes)
                    except Exception:
                        continue

    finally:
        os.unlink(tmp_path)

    return metadata


def get_image_metadata(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes))
        return {
            'format': img.format,
            'size': img.size,
            'mode': img.mode,
            'exif': img.getexif().get_ifd(0x8825) if hasattr(img, '_getexif') else None,
        }
    except Exception as e:
        return str(e)


def find_sensitive_patterns(text):
    patterns = {
        # Even more robust email pattern
        'emails_and_mailtos': r'(?:mailto:)?(?:[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-zA-Z0-9-]*[a-zA-Z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])',
        'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'network_paths': r'\\\\[a-zA-Z0-9\-_]+\\[a-zA-Z0-9\-_$]+(?:\\[a-zA-Z0-9\-_$]+)*',
        'local_paths': r'[A-Za-z]:\\[^<>:"|?*\n\r]+',
        'usernames': r'(?i)user(?:name)?["\'\s:]+([a-zA-Z0-9\-_@\.]+)',
        'api_keys': r'(?i)(api[_-]?key|access[_-]?token)["\'\s:]+([a-zA-Z0-9\-_]{16,})',
        'urls': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*',
        'social_security': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_cards': r'\b(?:\d[ -]*?){13,16}\b',
        'phone_numbers': r'\b(?:\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'
    }

    results = {}
    for pattern_name, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            # Handle both single matches and tuple matches from groups
            cleaned_matches = []
            for match in matches:
                if isinstance(match, tuple):
                    cleaned_matches.extend(m for m in match if m)
                else:
                    cleaned_matches.append(match)
            results[pattern_name] = list(set(cleaned_matches))
    return results


st.title("Document Metadata Analyzer")

uploaded_file = st.file_uploader(
    "Upload a PDF or DOCX file", type=['pdf', 'docx'])

if uploaded_file:
    file_bytes = uploaded_file.read()
    file_type = uploaded_file.type

    st.write("### File Information")
    st.write(f"Filename: {uploaded_file.name}")
    st.write(f"File type: {file_type}")

    try:
        if file_type == 'application/pdf':
            metadata = analyze_pdf(file_bytes)

            st.write("### PDF Basic Metadata")
            st.json(metadata.get('basic', {}))

            if metadata.get('content'):
                if metadata['content']['annotations']:
                    st.write("### Annotations Found")
                    st.json(metadata['content']['annotations'])

                if metadata['content']['links']:
                    st.write("### Links Found")
                    st.json(metadata['content']['links'])

                if metadata['content']['forms']:
                    st.write("### Form Fields Found")
                    st.json(metadata['content']['forms'])

            if metadata.get('images'):
                st.write("### Embedded Images")
                st.json(metadata['images'])

            if metadata.get('sensitive_data'):
                st.write("### Sensitive Data Found")
                st.json(metadata['sensitive_data'])

        elif file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            metadata = analyze_docx(file_bytes)

            st.write("### DOCX File Metadata")
            if metadata.get('file_metadata'):
                # Display in a more organized way
                for key, value in metadata['file_metadata'].items():
                    st.write(f"**{key.replace('_', ' ')}:** {value}")

            if metadata.get('statistics'):
                st.write("### Document Statistics")
                st.json(metadata['statistics'])

            if metadata.get('zip_contents'):
                st.write("### Document Structure")
                st.write("#### Files in Archive")
                st.json(metadata['zip_contents']['files'])

            if metadata.get('sensitive_data'):
                st.write("### Sensitive Data Found")
                st.json(metadata['sensitive_data'])

            if metadata.get('embedded_images'):
                st.write("### Embedded Images Metadata")
                st.json(metadata['embedded_images'])

    except Exception as e:
        st.error(f"Error analyzing file: {str(e)}")
