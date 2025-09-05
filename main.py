"""
PDF Section Redactor - Targeted Content Detection
Production-ready FastAPI application for redacting sensitive sections from PDF documents.
"""

import fitz  # PyMuPDF
import re
import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Tuple, Optional
import io
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="PDF Section Redactor API",
    description="Redact sensitive medical sections from PDF documents using targeted content detection",
    version="4.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for web access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure based on your needs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PDFSectionRedactor:
    def __init__(self):
        # Define the sections to redact (case-insensitive)
        self.target_sections = [
            "Past History",
            "History", 
            "Overview Note",
            "Family History",
            "History (continued)",
            "Substance & Sexuality History",
            "Past Surgical History",
            "Social History"
        ]
        
        # Add colon detection for problematic sections
        self.section_patterns = []
        for section in self.target_sections:
            escaped_section = re.escape(section)
            
            # Original pattern (keep for backward compatibility)
            original_pattern = re.compile(
                rf'^{escaped_section}\s*(?:\s+as\s+of\s+\d+/\d+/\d+)?$', 
                re.IGNORECASE | re.MULTILINE
            )
            self.section_patterns.append((section, original_pattern))
            
            # Add colon pattern for specific sections that need it
            if section in ["Past Surgical History", "Past History", "Social History"]:
                colon_pattern = re.compile(
                    rf'^{escaped_section}\s*:\s*$', 
                    re.IGNORECASE | re.MULTILINE
                )
                self.section_patterns.append((section, colon_pattern))
            
        # Also create patterns for common variations
        additional_patterns = [
            (re.compile(r'^History\s*\([^)]*\)\s*$', re.IGNORECASE | re.MULTILINE), "History (continued)"),
            (re.compile(r'^Family\s+Histor[y]?\s*$', re.IGNORECASE | re.MULTILINE), "Family History"),
        ]
        
        for pattern, section_name in additional_patterns:
            self.section_patterns.append((section_name, pattern))
            
        # Define known section headers that should stop redaction
        self.major_section_headers = [
            "allergies", "immunizations", "implants", "visit list", 
            "medication list", "procedures", "discharge", "vitals",
            "treatment team", "documents", "flowsheets", "physical exam",
            "assessment", "plan", "chief complaint", "hpi", "ros",
            "review of systems", "labs", "radiology", "pathology",
            "current medications", "problem list", "orders", "notes",
            "diagnostic results", "imaging", "consultation", "discharge summary"
        ]
        
        # Define medical procedure content patterns to detect
        self.medical_procedure_patterns = [
            r'plan\s+excision',
            r'plan\s+debridement',
            r'plan\s+fusion',
            r'plan\s+surgery',
            r'plan\s+procedure',
            r'plan\s+wound',
            r'currently\s+in\s+surgical\s+shoe',
            r'cleanses\s+daily',
            r'applies\s+.*?ointment',
            r'applies\s+.*?abx',
            r'dsd\s*$',
            r'excision\s+and\s+debridement',
            r'surgical\s+shoe',
            r'wound\s+care',
            r'post\s*[-\s]*op',
            r'follow\s*[-\s]*up'
        ]
        
        # Define sections that should trigger targeted content detection
        self.targeted_detection_sections = [
            "Past Surgical History",
            "Past History"
        ]
        
        # Detection range (in points) to scan after target sections
        self.detection_range = 75  # Smaller than previous extensions
    
    def extract_text_blocks_with_coordinates(self, page) -> List[Dict]:
        """Extract text blocks with their coordinates and formatting info"""
        text_dict = page.get_text("dict")
        blocks = []
        
        for block in text_dict["blocks"]:
            if "lines" in block:  # Text block
                for line in block["lines"]:
                    for span in line["spans"]:
                        text = span["text"].strip()
                        if text:  # Only include non-empty text
                            blocks.append({
                                "text": text,
                                "bbox": span["bbox"],  # (x0, y0, x1, y1)
                                "font": span["font"],
                                "size": span["size"],
                                "flags": span["flags"]
                            })
        
        # Sort blocks by y-coordinate (top to bottom)
        blocks.sort(key=lambda x: x["bbox"][1])
        return blocks
    
    def is_section_header(self, text: str, font_size: float, flags: int) -> Tuple[bool, Optional[str]]:
        """
        Determine if a text block is a section header we want to redact
        Returns (is_header, section_name)
        """
        text = text.strip()
        if not text:
            return False, None
            
        # Check against our target sections
        for section_name, pattern in self.section_patterns:
            if pattern.match(text):
                return True, section_name
                
        return False, None
    
    def is_medical_procedure_content(self, text: str) -> bool:
        """
        Check if text contains medical procedure content that should be redacted
        """
        text_lower = text.strip().lower()
        
        for pattern in self.medical_procedure_patterns:
            if re.search(pattern, text_lower):
                logger.info(f"Found medical procedure content: '{text}' (pattern: {pattern})")
                return True
        
        return False
    
    def is_major_section_boundary(self, text: str, block: Dict) -> bool:
        """Determine if this text represents a new major section that should end redaction"""
        text_lower = text.strip().lower()
        
        # Check if this looks like a major section header
        for section in self.major_section_headers:
            if text_lower.startswith(section):
                # Additional checks to ensure it's actually a header
                if (len(text) < 100 and  # Not too long
                    not text.endswith(".") and  # Not a sentence
                    (text.isupper() or text.istitle() or  # Formatted like header
                     block["size"] >= 10)):  # Reasonable font size
                    return True
                    
        return False
    
    def find_targeted_content_in_range(self, page, start_y: float, end_y: float) -> List[Dict]:
        """
        Look for medical procedure content in a specific y-coordinate range
        """
        blocks = self.extract_text_blocks_with_coordinates(page)
        found_content = []
        
        for block in blocks:
            block_y = block["bbox"][1]
            
            # Check if block is in our detection range
            if start_y <= block_y <= end_y:
                if self.is_medical_procedure_content(block["text"]):
                    found_content.append(block)
                    logger.info(f"Found targeted content at y={block_y}: '{block['text']}'")
        
        return found_content
    
    def find_global_section_boundaries_with_targeted_detection(self, pdf_doc) -> List[Dict]:
        """
        Find section boundaries and add targeted content detection
        """
        all_sections = []
        current_section = None
        section_start_page = None
        section_start_y = None
        
        for page_num in range(pdf_doc.page_count):
            page = pdf_doc[page_num]
            blocks = self.extract_text_blocks_with_coordinates(page)
            
            for block in blocks:
                text = block["text"]
                bbox = block["bbox"]
                
                # Check if this is a target section header
                is_header, section_name = self.is_section_header(
                    text, block["size"], block["flags"]
                )
                
                if is_header:
                    # If we were already in a section, close it with targeted detection
                    if current_section:
                        extended_end_y = self.apply_targeted_detection(
                            current_section, section_start_page, section_start_y, 
                            page_num, bbox[1], pdf_doc
                        )
                        
                        all_sections.append({
                            "section": current_section,
                            "start_page": section_start_page,
                            "start_y": section_start_y,
                            "end_page": page_num,
                            "end_y": extended_end_y,
                            "original_end_y": bbox[1]
                        })
                    
                    # Start new section
                    current_section = section_name
                    section_start_page = page_num
                    section_start_y = bbox[1]
                    
                    logger.info(f"Started redacting section '{section_name}' on page {page_num + 1}")
                
                elif current_section and self.is_major_section_boundary(text, block):
                    # Close current section with targeted detection
                    extended_end_y = self.apply_targeted_detection(
                        current_section, section_start_page, section_start_y, 
                        page_num, bbox[1], pdf_doc
                    )
                    
                    all_sections.append({
                        "section": current_section,
                        "start_page": section_start_page,
                        "start_y": section_start_y,
                        "end_page": page_num,
                        "end_y": extended_end_y,
                        "original_end_y": bbox[1]
                    })
                    
                    logger.info(f"Ended redacting section '{current_section}' at '{text}' on page {page_num + 1}")
                    current_section = None
                    section_start_page = None
                    section_start_y = None
        
        # If we end with a section still open, close it at the last page
        if current_section:
            last_page = pdf_doc[pdf_doc.page_count - 1]
            page_height = last_page.rect.height
            
            extended_end_y = self.apply_targeted_detection(
                current_section, section_start_page, section_start_y, 
                pdf_doc.page_count - 1, page_height, pdf_doc
            )
            
            all_sections.append({
                "section": current_section,
                "start_page": section_start_page,
                "start_y": section_start_y,
                "end_page": pdf_doc.page_count - 1,
                "end_y": extended_end_y,
                "original_end_y": page_height
            })
            
            logger.info(f"Ended redacting section '{current_section}' at end of document")
        
        return all_sections
    
    def apply_targeted_detection(self, section_name: str, start_page: int, start_y: float, 
                                end_page: int, original_end_y: float, pdf_doc) -> float:
        """
        Apply targeted content detection for specific sections
        """
        # Only apply targeted detection for specific sections
        if section_name not in self.targeted_detection_sections:
            return original_end_y
        
        page = pdf_doc[end_page]
        page_height = page.rect.height
        
        # Define detection range
        detection_end_y = min(original_end_y + self.detection_range, page_height)
        
        # Look for medical procedure content in the detection range
        found_content = self.find_targeted_content_in_range(page, original_end_y, detection_end_y)
        
        if found_content:
            # Find the lowest y-coordinate of found content
            max_content_y = max(block["bbox"][3] for block in found_content)  # bbox[3] is bottom of text
            
            # Check if extending would hit a major section boundary
            blocks = self.extract_text_blocks_with_coordinates(page)
            for block in blocks:
                block_y = block["bbox"][1]
                if original_end_y < block_y < max_content_y + 10:  # Small buffer
                    if self.is_major_section_boundary(block["text"], block):
                        logger.info(f"Targeted detection stopped by section boundary: '{block['text']}'")
                        return original_end_y  # Don't extend past section boundary
            
            extended_end_y = max_content_y + 5  # Small buffer below content
            logger.info(f"Targeted detection extended '{section_name}' from y={original_end_y} to y={extended_end_y}")
            return extended_end_y
        
        # No targeted content found, use original boundary
        return original_end_y
    
    def apply_redaction_to_pages(self, pdf_doc, section_info: Dict):
        """Apply redaction across multiple pages for a single section"""
        start_page = section_info["start_page"]
        end_page = section_info["end_page"]
        start_y = section_info["start_y"]
        end_y = section_info["end_y"]
        section_name = section_info["section"]
        
        logger.info(f"Redacting section '{section_name}' from page {start_page + 1} to page {end_page + 1}")
        
        for page_num in range(start_page, end_page + 1):
            page = pdf_doc[page_num]
            page_width = page.rect.width
            page_height = page.rect.height
            
            if page_num == start_page and page_num == end_page:
                # Section starts and ends on the same page
                rect = fitz.Rect(0, start_y, page_width, end_y)
            elif page_num == start_page:
                # First page of section - from start_y to bottom
                rect = fitz.Rect(0, start_y, page_width, page_height)
            elif page_num == end_page:
                # Last page of section - from top to end_y
                rect = fitz.Rect(0, 0, page_width, end_y)
            else:
                # Middle page - redact entire page
                rect = fitz.Rect(0, 0, page_width, page_height)
            
            # Add redaction annotation
            redact_annot = page.add_redact_annot(rect)
            redact_annot.set_colors(fill=(0, 0, 0))  # Black fill
            redact_annot.update()
            
            # Apply redaction immediately for this page
            page.apply_redactions()
            
            logger.info(f"Applied redaction on page {page_num + 1}")
    
    def redact_pdf(self, pdf_bytes: bytes) -> bytes:
        """Main redaction function with targeted content detection"""
        try:
            # Open PDF document
            pdf_doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            
            # Find all sections to redact with targeted detection
            sections_to_redact = self.find_global_section_boundaries_with_targeted_detection(pdf_doc)
            
            logger.info(f"Found {len(sections_to_redact)} sections to redact")
            
            # Apply redactions for each section
            for section_info in sections_to_redact:
                self.apply_redaction_to_pages(pdf_doc, section_info)
            
            logger.info(f"Completed redaction of {len(sections_to_redact)} sections")
            
            # Save redacted PDF
            output_bytes = pdf_doc.tobytes()
            pdf_doc.close()
            
            return output_bytes
            
        except Exception as e:
            logger.error(f"Error during redaction: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Redaction failed: {str(e)}")

# Initialize the redactor
redactor = PDFSectionRedactor()

@app.get("/")
def read_root():
    """Root endpoint with API information"""
    return {
        "message": "PDF Section Redactor API - Targeted Content Detection", 
        "version": "4.0.0",
        "status": "online",
        "endpoints": {
            "redact": "/redact-pdf",
            "sections": "/sections",
            "health": "/health",
            "docs": "/docs"
        },
        "approach": "Targeted pattern-based content detection",
        "target_sections": redactor.target_sections
    }

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "service": "pdf-targeted-detection-redactor",
        "version": "4.0.0"
    }

@app.post("/redact-pdf")
async def redact_pdf_endpoint(file: UploadFile = File(...)):
    """
    Redact sensitive sections from a PDF file using targeted content detection
    
    - **file**: PDF file to redact (multipart/form-data)
    - **returns**: Redacted PDF with specified sections permanently removed
    """
    
    # Validate file type
    if not file.content_type == "application/pdf":
        raise HTTPException(
            status_code=400, 
            detail="File must be a PDF. Received: " + str(file.content_type)
        )
    
    # Validate file size (max 50MB)
    max_size = 50 * 1024 * 1024  # 50MB
    
    try:
        # Read uploaded file
        pdf_content = await file.read()
        
        if len(pdf_content) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
        
        if len(pdf_content) > max_size:
            raise HTTPException(
                status_code=413, 
                detail=f"File too large. Max size: {max_size // (1024*1024)}MB"
            )
        
        logger.info(f"Processing PDF: {file.filename}, Size: {len(pdf_content)} bytes")
        
        # Perform redaction
        redacted_pdf = redactor.redact_pdf(pdf_content)
        
        # Generate filename
        original_name = file.filename or "document.pdf"
        redacted_filename = f"redacted_{original_name}"
        
        # Return redacted PDF
        return Response(
            content=redacted_pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={redacted_filename}",
                "Content-Length": str(len(redacted_pdf))
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing {file.filename}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="Internal server error occurred during PDF processing"
        )

@app.get("/sections")
def get_target_sections():
    """Get detailed information about redaction sections and patterns"""
    return {
        "target_sections": redactor.target_sections,
        "major_section_boundaries": redactor.major_section_headers,
        "medical_procedure_patterns": redactor.medical_procedure_patterns,
        "targeted_detection_sections": redactor.targeted_detection_sections,
        "detection_range_points": redactor.detection_range,
        "redaction_type": "TRUE redaction - text permanently removed",
        "description": "Targeted content detection approach - hunts for specific medical procedure patterns",
        "api_info": {
            "max_file_size": "50MB",
            "supported_formats": ["PDF"],
            "output_format": "PDF"
        }
    }

# Error handlers
@app.exception_handler(413)
async def payload_too_large_handler(request, exc):
    return {"error": "File too large", "max_size": "50MB"}

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return {"error": "Internal server error", "message": "Please try again later"}

if __name__ == "__main__":
    import uvicorn
    # For local development
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")