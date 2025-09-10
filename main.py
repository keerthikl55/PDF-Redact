"""
PDF Section Redactor - Enhanced Sensitive Content Detection
Production-ready FastAPI application for redacting sensitive sections AND specific sensitive content from PDF documents.
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
    title="PDF Section Redactor API - Enhanced Sensitive Content Detection",
    description="Redact sensitive medical sections AND detect/redact especially private medical information",
    version="5.0.1",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for web access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PDFSectionRedactor:
    def __init__(self):
        # Define the sections to redact (case-insensitive)
        self.target_sections = [
            "Past History",
            "Past Medical History",
            "Medical History",
            "Overview Note",
            "Family History",
            "History (continued)",
            "Substance & Sexuality History",
            "Past Surgical History",
            "Social History",
            "Psychiatric History",
            "Medication List",
            "Medication List (continued)",
            "Discharge Medication List",
            "Prior to Admission medications",
            "Prior to Admission Medications",
            "Medications Prior to Admission",
            "Pre-Admission Medications",
            "Current Medications",
            "Home Medications",
            "Outpatient Medications"
            "Problem List",
            "Revision History"
        ]
        
        # NEW: Define especially sensitive medical content patterns
        self.sensitive_content_patterns = [

            # Alcohol-related patterns
            r'\balcohol\b',   # NEW: catch standalone alcohol
            r'\balcohol abuse\b',
            r'\balcoholic\b',
            r'\balcoholism\b',
            r'\balcohol dependence\b',

            # Mental Health Conditions
            r'\b(depression|depressed|depressive|major depression|clinical depression)\b',
            r'\b(anxiety|anxious|panic disorder|panic attacks|generalized anxiety)\b',
            r'\b(bipolar|manic|mania|manic episode|mood disorder)\b',
            r'\b(schizophrenia|psychotic|psychosis|hallucination|delusion)\b',
            r'\b(ptsd|post[-\s]?traumatic stress|trauma|traumatic)\b',
            r'\b(suicidal|suicide|self[-\s]?harm|suicidal ideation)\b',
            # r'\b(psychiatric|mental health|psychological|therapy|counseling)\b',
            
            # Substance Abuse
            r'\b(alcohol abuse|alcoholic|alcoholism|alcohol dependence)\b',
            r'\b(drug abuse|substance abuse|addiction|dependent on|addicted to)\b',
            r'\b(tobacco use|smoker|smoking|cigarette|pack[-\s]?years)\b',
            r'\b(cocaine|heroin|methamphetamine|opioid|opiate|marijuana|cannabis)\b',
            r'\b(rehab|rehabilitation|detox|detoxification|withdrawal)\b',
            r'\b(aa|alcoholics anonymous|na|narcotics anonymous)\b',
            
            # # HIV/AIDS and STDs
            r'\b(hiv|aids|human immunodeficiency virus)\b',
            r'\b(std|sti|sexually transmitted|gonorrhea|chlamydia|syphilis)\b',
            r'\b(herpes|hpv|human papillomavirus|hepatitis b|hepatitis c)\b',
            
            # Hepatitis (all types)
            r'\b(hepatitis|hep a|hep b|hep c|viral hepatitis)\b',
            
            # Physical/Domestic Abuse
            r'\b(domestic violence|domestic abuse|physical abuse|sexual abuse)\b',
            r'\b(assault|battered|beaten|abused|violence|violent)\b',
            r'\b(restraining order|protective order|abuse counseling)\b',
            
            # Genetic Testing
            r'\b(genetic test|genetic screening|gene test|dna test)\b',
            r'\b(brca|genetic mutation|hereditary|familial syndrome)\b',
            r'\b(genetic counseling|chromosomal|carrier status)\b',
            
            # Reproductive/Sexual Health
            r'\b(pregnancy test|pregnant|abortion|miscarriage|stillbirth)\b',
            r'\b(contraception|birth control|sexual dysfunction|impotence)\b',
            r'\b(fertility|infertility|ivf|reproductive health)\b',
            
            # Additional sensitive patterns with measurements
            r'cigarette pack[-\s]?years\s*[=:]\s*\d+',
            r'drinks\s+per\s+day\s*[=:]\s*\d+',
            r'packs\s+per\s+day\s*[=:]\s*\d+',
            r'years\s+of\s+(smoking|drinking|drug use)',
        ]
        
        # Compile sensitive content patterns for performance
        self.compiled_sensitive_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
            for pattern in self.sensitive_content_patterns
        ]
        
        # Add colon detection for section headers
        self.section_patterns = []
        for section in self.target_sections:
            escaped_section = re.escape(section)
            
            # Original pattern
            original_pattern = re.compile(
                rf'^{escaped_section}\s*(?:\s+as\s+of\s+\d+/\d+/\d+)?$', 
                re.IGNORECASE | re.MULTILINE
            )
            self.section_patterns.append((section, original_pattern))
            
            # Colon pattern
            colon_pattern = re.compile(
                rf'^{escaped_section}\s*:\s*$', 
                re.IGNORECASE | re.MULTILINE
            )
            self.section_patterns.append((section, colon_pattern))
            
        # Additional section patterns - FIXED: Removed ED Provider Note patterns
        additional_patterns = [
            # More specific History (continued) pattern to avoid conflicts
            (re.compile(r'^(?:Past\s+)?(?:Medical\s+)?History\s*\([^)]*\)\s*$', re.IGNORECASE | re.MULTILINE), "History (continued)"),
            (re.compile(r'^Family\s+Histor[y]?\s*$', re.IGNORECASE | re.MULTILINE), "Family History"),
            (re.compile(r'^Past\s+Medical\s+History\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Past Medical History"),
            (re.compile(r'^Medical\s+History\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Medical History"),
            (re.compile(r'^Medications?\s*List\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Medication List"),
            (re.compile(r'^Medications?\s*List\s*\([^)]*\)\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Medication List (continued)"),
            (re.compile(r'^Discharge\s+Medications?\s*List\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Discharge Medication List"),
            (re.compile(r'^Prior\s+to\s+Admission\s+[Mm]edications?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Prior to Admission medications"),
            (re.compile(r'^[Mm]edications?\s+Prior\s+to\s+Admission\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Medications Prior to Admission"),
            (re.compile(r'^Pre[\s-]*Admission\s+[Mm]edications?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Pre-Admission Medications"),
            (re.compile(r'^Current\s+[Mm]edications?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Current Medications"),
            (re.compile(r'^Home\s+[Mm]edications?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Home Medications"),
            (re.compile(r'^Outpatient\s+[Mm]edications?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Outpatient Medications"),
            (re.compile(r'^[Mm]eds?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Medication List"),
            (re.compile(r'^[Mm]edication\s+[Hh]istory\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Medication List"),
            (re.compile(r'^Discharge\s+[Mm]eds?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Discharge Medication List"),
            # REMOVED: ED Provider Note patterns - these should NOT be redacted
            # NEW: Problem List patterns
            (re.compile(r'^Problem\s+List\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Problem List"),
            # (re.compile(r'^Problems?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Problem List"),
            # (re.compile(r'^Active\s+Problems?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Problem List"),
            # (re.compile(r'^Current\s+Problems?\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Problem List"),
            
            # NEW: Revision History patterns
            (re.compile(r'^Revision\s+History\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Revision History"),
            # (re.compile(r'^Document\s+History\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Revision History"),
            # (re.compile(r'^Version\s+History\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Revision History"),
            # (re.compile(r'^Edit\s+History\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Revision History"),
            # (re.compile(r'^Change\s+History\s*:?\s*$', re.IGNORECASE | re.MULTILINE), "Revision History"),
        ]
        
        for pattern, section_name in additional_patterns:
            self.section_patterns.append((section_name, pattern))
            
        # Define known section headers that should stop redaction
        self.major_section_headers = [
            "allergies", "immunizations", "implants", "visit list", 
            "procedures", "discharge", "vitals",
            "treatment team", "documents", "flowsheets", "physical exam",
            "assessment", "plan", "chief complaint", "hpi", "ros",
            "review of systems", "labs", "radiology", "pathology",
            "orders", "notes",
            "diagnostic results", "imaging", "consultation", "discharge summary", 
            "coding summary", "visit information", "appointment information",
            "hospital account", "account information", "admission information",
            # ADDED: Provider notes should stop redaction
            "ed provider note", "provider note", "physician note", "doctor note",
            "attending note", "resident note", "nurse note", "nursing note",
            # COMPREHENSIVE Provider note boundaries - ANY of these will STOP redaction
            "ed provider note", "ed provider notes",  # Added plural form
            "emergency department provider note", "emergency department provider notes",
            "emergency dept provider note", "emergency dept provider notes", 
            "er provider note", "er provider notes",
            "provider note", "provider notes",
            "physician note", "physician notes",
            "doctor note", "doctor notes",
            "attending note", "attending notes",
            "resident note", "resident notes", 
            "nurse note", "nurse notes",
            "nursing note", "nursing notes",
            "clinical note", "clinical notes",
            "progress note", "progress notes",
            "consultation note", "consultation notes",
            "ed note", "ed notes",
            "emergency note", "emergency notes",
            "provider documentation", "clinical documentation",
            # ADDED: Medication list boundaries
            "stopped in visit", "stopped in", "service date", "chief complaint"
        ]
        
        # Define medical procedure content patterns
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
            r'follow\s*[-\s]*up',
            r'\d+\s*mg\s+.*?(daily|bid|tid|qid|qhs|prn)',
            r'take\s+\d+.*?(daily|twice|morning|evening)',
            r'(tablet|capsule|pill)s?\s+.*?(daily|bid|tid)',
            r'dosage\s*:',
            r'frequency\s*:',
            r'rx\s*:',
            r'sig\s*:',
            r'disp\s*:',
            r'refills?\s*:',
            r'\b(lisinopril|metformin|atorvastatin|amlodipine|metoprolol|omeprazole|levothyroxine|gabapentin|hydrochlorothiazide|sertraline)\b'
        ]
        
        # Define sections that should trigger targeted content detection
        self.targeted_detection_sections = [
            "Past Surgical History",
            "Past History",
            "Past Medical History",
            "Medical History",
            "Medication List",
            "Medication List (continued)",
            "Discharge Medication List",
            "Prior to Admission medications",
            "Current Medications",
            "Home Medications"
        ]
        
        # Detection range (in points) to scan after target sections
        self.detection_range = 100

    def is_administrative_context(self, page, text_y_position: float) -> bool:
        """Check if we're in an administrative section by looking at nearby text above this position"""
        blocks = self.extract_text_blocks_with_coordinates(page)
        
        context_window = 150
        
        for block in blocks:
            block_y = block["bbox"][1]
            
            if (text_y_position - context_window) <= block_y < text_y_position:
                text_lower = block["text"].lower().strip()
                
                admin_indicators = [
                    "visit information", "appointment information", 
                    "hospital account", "account information",
                    "billing", "insurance", "provider information",
                    "referral provider", "admission information",
                    "patient information", "demographics"
                ]
                
                for indicator in admin_indicators:
                    if indicator in text_lower:
                        logger.info(f"Found administrative context: '{block['text']}' above position {text_y_position}")
                        return True
        
        return False

    def contains_sensitive_content(self, text: str) -> Tuple[bool, List[str]]:
        """
        NEW: Check if text contains especially sensitive medical information
        Returns (has_sensitive_content, list_of_matched_patterns)
        """
        if not text or len(text.strip()) < 3:
            return False, []
        
        matched_patterns = []
        text_clean = text.strip()
        
        for i, pattern in enumerate(self.compiled_sensitive_patterns):
            if pattern.search(text_clean):
                matched_patterns.append(self.sensitive_content_patterns[i])
                
        if matched_patterns:
            logger.info(f"Found sensitive content: '{text_clean[:100]}...' (patterns: {len(matched_patterns)})")
            return True, matched_patterns
        
        return False, []

    def find_sensitive_content_blocks(self, pdf_doc) -> List[Dict]:
        """
        NEW: Scan entire document for sensitive content blocks that need redaction
        """
        sensitive_blocks = []
        
        for page_num in range(pdf_doc.page_count):
            page = pdf_doc[page_num]
            blocks = self.extract_text_blocks_with_coordinates(page)
            
            for block in blocks:
                text = block["text"]
                has_sensitive, patterns = self.contains_sensitive_content(text)
                
                if has_sensitive:
                    # Skip if this is in administrative context
                    if self.is_administrative_context(page, block["bbox"][1]):
                        continue
                        
                    sensitive_blocks.append({
                        "page": page_num,
                        "bbox": block["bbox"],
                        "text": text,
                        "matched_patterns": patterns,
                        "block_type": "sensitive_content"
                    })
                    
                    logger.info(f"Found sensitive content on page {page_num + 1}: '{text[:50]}...'")
        
        return sensitive_blocks

    def debug_section_detection(self, pdf_doc):
        """Debug method to see what sections and sensitive content are being detected"""
        for page_num in range(min(3, pdf_doc.page_count)):
            page = pdf_doc[page_num]
            blocks = self.extract_text_blocks_with_coordinates(page)
            
            print(f"\n=== PAGE {page_num + 1} DEBUG ===")
            for i, block in enumerate(blocks[:25]):
                text = block["text"].strip()
                if len(text) > 2:
                    is_header, section_name = self.is_section_header(text, block["size"], block["flags"], page, block["bbox"][1])
                    is_boundary = self.is_major_section_boundary(text, block)
                    is_admin = self.is_administrative_context(page, block["bbox"][1])
                    has_sensitive, patterns = self.contains_sensitive_content(text)
                    
                    status = ""
                    if is_header:
                        status += f" [REDACT SECTION: {section_name}]"
                    if is_boundary:
                        status += " [STOP BOUNDARY]"
                    if is_admin:
                        status += " [ADMIN CONTEXT]"
                    if has_sensitive:
                        status += f" [SENSITIVE CONTENT: {len(patterns)} patterns]"
                    
                    print(f"{i:2d}: '{text}'{status}")
        
        print("\n" + "="*50)
    
    def extract_text_blocks_with_coordinates(self, page) -> List[Dict]:
        """Extract text blocks with their coordinates and formatting info"""
        text_dict = page.get_text("dict")
        blocks = []
        
        for block in text_dict["blocks"]:
            if "lines" in block:
                for line in block["lines"]:
                    for span in line["spans"]:
                        text = span["text"].strip()
                        if text:
                            blocks.append({
                                "text": text,
                                "bbox": span["bbox"],
                                "font": span["font"],
                                "size": span["size"],
                                "flags": span["flags"]
                            })
        
        blocks.sort(key=lambda x: x["bbox"][1])
        return blocks
    
    def is_section_header(self, text: str, font_size: float, flags: int, page=None, y_position: float = None) -> Tuple[bool, Optional[str]]:
        """Determine if a text block is a section header we want to redact"""
        text = text.strip()
        if not text or len(text) < 4:
            return False, None

        # ADDED: Explicitly exclude provider notes that should NOT be redacted
        provider_note_patterns = [
            r'^ED\s+Provider\s+Note',
            r'^Emergency\s+Department\s+Provider\s+Note',
            r'^Provider\s+Note',
            r'^Physician\s+Note', 
            r'^Doctor\s+Note',
            r'^Attending\s+Note',
            r'^Resident\s+Note',
            r'^Nurse\s+Note',
            r'^Nursing\s+Note'
        ]
        
        for pattern in provider_note_patterns:
            if re.match(pattern, text, re.IGNORECASE):
                logger.info(f"Skipping provider note (should NOT be redacted): '{text}'")
                return False, None
        
        if page and y_position and self.is_administrative_context(page, y_position):
            logger.info(f"Skipping '{text}' - in administrative context")
            return False, None
            
        for section_name, pattern in self.section_patterns:
            if pattern.match(text):
                logger.info(f"Found medical section to redact: '{text}' -> {section_name}")
                return True, section_name
                
        return False, None
    
    def is_medical_procedure_content(self, text: str) -> bool:
        """Check if text contains medical procedure content that should be redacted"""
        text_lower = text.strip().lower()
        
        for pattern in self.medical_procedure_patterns:
            if re.search(pattern, text_lower):
                logger.info(f"Found medical procedure content: '{text}' (pattern: {pattern})")
                return True
        
        return False
    
    def is_major_section_boundary(self, text: str, block: Dict) -> bool:
        """Enhanced boundary detection that explicitly protects provider notes"""
        text_lower = text.strip().lower()
        
        # First check if this is a provider note that should STOP redaction
        if self.is_provider_note(text):
            return True
        
        # Then check other major section headers
        for section in self.major_section_headers:
            if text_lower.startswith(section):
                if (len(text) < 100 and
                    not text.endswith(".") and
                    (text.isupper() or text.istitle() or block["size"] >= 10)):
                    logger.info(f"Found section boundary: '{text}' (stops redaction)")
                    return True
                    
        return False
    
    def find_targeted_content_in_range(self, page, start_y: float, end_y: float) -> List[Dict]:
        """Look for medical procedure content in a specific y-coordinate range"""
        blocks = self.extract_text_blocks_with_coordinates(page)
        found_content = []
        
        for block in blocks:
            block_y = block["bbox"][1]
            
            if start_y <= block_y <= end_y:
                if self.is_medical_procedure_content(block["text"]):
                    found_content.append(block)
                    logger.info(f"Found targeted content at y={block_y}: '{block['text']}'")
        
        return found_content
    
    def find_global_section_boundaries_with_targeted_detection(self, pdf_doc) -> List[Dict]:
        """Find section boundaries and add targeted content detection - ENHANCED for ED Provider Notes"""
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
                
                # ENHANCED: Check for provider notes FIRST before checking section headers
                is_provider_note = self.is_provider_note(text)
                
                if is_provider_note and current_section:
                    # Provider note should END the current redaction section
                    extended_end_y = self.apply_targeted_detection(
                        current_section, section_start_page, section_start_y, 
                        page_num, bbox[1], pdf_doc
                    )
                    
                    all_sections.append({
                        "section": current_section,
                        "start_page": section_start_page,
                        "start_y": section_start_y,
                        "end_page": page_num,
                        "end_y": min(extended_end_y, bbox[1]),  # Stop BEFORE provider note
                        "original_end_y": bbox[1]
                    })
                    
                    logger.info(f"Ended redacting section '{current_section}' before ED Provider Note on page {page_num + 1}")
                    current_section = None
                    section_start_page = None
                    section_start_y = None
                    continue
                
                is_header, section_name = self.is_section_header(
                    text, block["size"], block["flags"], page, bbox[1]
                )
                
                if is_header:
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
                    
                    current_section = section_name
                    section_start_page = page_num
                    section_start_y = bbox[1]
                    
                    logger.info(f"Started redacting section '{section_name}' on page {page_num + 1}")
                
                elif current_section and self.is_major_section_boundary(text, block):
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
        
        # Handle section that goes to end of document
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
    
    def is_provider_note(self, text: str) -> bool:
        """Check if text is a provider note that should stop redaction"""
        text = text.strip()
        if not text:
            return False
        
        provider_note_patterns = [
            r'^ED\s+Provider\s+Note\b',
            r'^Emergency\s+Department\s+Provider\s+Note\b',
            r'^Emergency\s+Dept\s+Provider\s+Note\b',
            r'^ER\s+Provider\s+Note\b',
            r'^Provider\s+Note\b',
            r'^Physician\s+Note\b',
            r'^Doctor\s+Note\b',
            r'^Attending\s+Note\b',
            r'^Resident\s+Note\b',
            r'^Nurse\s+Note\b',
            r'^Nursing\s+Note\b',
            r'^Clinical\s+Note\b',
            r'^Progress\s+Note\b',
            r'^Consultation\s+Note\b',
            r'^ED\s+Note\b',
            r'^Emergency\s+Note\b'
        ]
        
        for pattern in provider_note_patterns:
            if re.match(pattern, text, re.IGNORECASE):
                logger.info(f"🛡️ BOUNDARY: Provider note will stop redaction: '{text}'")
                return True
        
        return False
    
    def apply_targeted_detection(self, section_name: str, start_page: int, start_y: float, 
                                end_page: int, original_end_y: float, pdf_doc) -> float:
        """Apply targeted content detection for specific sections"""
        if section_name not in self.targeted_detection_sections:
            return original_end_y
        
        page = pdf_doc[end_page]
        page_height = page.rect.height
        
        detection_end_y = min(original_end_y + self.detection_range, page_height)
        
        found_content = self.find_targeted_content_in_range(page, original_end_y, detection_end_y)
        
        if found_content:
            max_content_y = max(block["bbox"][3] for block in found_content)
            
            blocks = self.extract_text_blocks_with_coordinates(page)
            for block in blocks:
                block_y = block["bbox"][1]
                if original_end_y < block_y < max_content_y + 10:
                    if self.is_major_section_boundary(block["text"], block):
                        logger.info(f"Targeted detection stopped by section boundary: '{block['text']}'")
                        return original_end_y
            
            extended_end_y = max_content_y + 5
            logger.info(f"Targeted detection extended '{section_name}' from y={original_end_y} to y={extended_end_y}")
            return extended_end_y
        
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
                rect = fitz.Rect(0, start_y, page_width, end_y)
            elif page_num == start_page:
                rect = fitz.Rect(0, start_y, page_width, page_height)
            elif page_num == end_page:
                rect = fitz.Rect(0, 0, page_width, end_y)
            else:
                rect = fitz.Rect(0, 0, page_width, page_height)
            
            redact_annot = page.add_redact_annot(rect)
            redact_annot.set_colors(fill=(0, 0, 0))
            redact_annot.update()
            
            page.apply_redactions()
            
            logger.info(f"Applied section redaction on page {page_num + 1}")

    def apply_sensitive_content_redactions(self, pdf_doc, sensitive_blocks: List[Dict]):
        """
        Apply redactions to individual sensitive content blocks
        """
        logger.info(f"Applying redactions to {len(sensitive_blocks)} sensitive content blocks")
        
        for block_info in sensitive_blocks:
            page_num = block_info["page"]
            bbox = block_info["bbox"]
            
            page = pdf_doc[page_num]
            
            # Smaller padding (less vertical overlap)
            padding_x = 1   # left/right padding
            padding_y = 0.5 # top/bottom padding
            
            rect = fitz.Rect(
                bbox[0] - padding_x, 
                bbox[1] - padding_y, 
                bbox[2] + padding_x, 
                bbox[3] + padding_y
            )
            
            redact_annot = page.add_redact_annot(rect)
            redact_annot.set_colors(fill=(0, 0, 0))  # Black fill
            redact_annot.update()
            page.apply_redactions()
            
            logger.info(f"Redacted sensitive content on page {page_num + 1}: '{block_info['text'][:50]}...'")
    
    def redact_pdf(self, pdf_bytes: bytes, debug_mode: bool = False) -> bytes:
        """Main redaction function with section detection AND sensitive content detection"""
        try:
            pdf_doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            
            if debug_mode:
                self.debug_section_detection(pdf_doc)
            
            # Step 1: Find and redact medical sections
            sections_to_redact = self.find_global_section_boundaries_with_targeted_detection(pdf_doc)
            logger.info(f"Found {len(sections_to_redact)} sections to redact")
            
            for section_info in sections_to_redact:
                self.apply_redaction_to_pages(pdf_doc, section_info)
            
            # Step 2: NEW - Find and redact sensitive content throughout the document
            sensitive_blocks = self.find_sensitive_content_blocks(pdf_doc)
            logger.info(f"Found {len(sensitive_blocks)} sensitive content blocks to redact")
            
            if sensitive_blocks:
                self.apply_sensitive_content_redactions(pdf_doc, sensitive_blocks)
            
            logger.info(f"Completed redaction: {len(sections_to_redact)} sections + {len(sensitive_blocks)} sensitive content blocks")
            
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
        "message": "PDF Section Redactor API - Enhanced Sensitive Content Detection - Fixed ED Provider Note Issue", 
        "version": "5.0.1",
        "status": "online",
        "new_in_v5_1_0": [
            "Added Problem List redaction",
            "Added Revision History redaction",
            "Enhanced pattern matching for problem lists",
            "Support for various revision history formats"
        ],
        "fixes": [
            "Enhanced boundary detection for 'Stopped in Visit'",
            "Added specific boundary patterns to prevent overlap",
            "Fixed ED Provider Note over-redaction issue", 
            "Improved debug output with y-coordinates",
            "Added regex patterns for common boundaries"
        ],
        "new_features": [
            "Detects and redacts especially sensitive medical information",
            "Mental health conditions (depression, anxiety, PTSD, etc.)",
            "Substance abuse (alcohol, drugs, smoking, pack-years)",
            "HIV/AIDS, STDs, Hepatitis",
            "Physical/domestic abuse, violence",
            "Genetic testing information",
            "Reproductive health information",
            "Content-aware redaction (not just section headers)"
        ],
        "endpoints": {
            "redact": "/redact-pdf",
            "redact-debug": "/redact-pdf?debug=true",
            "sections": "/sections",
            "sensitive-patterns": "/sensitive-patterns",
            "health": "/health",
            "docs": "/docs"
        },
        "approach": "Section detection + Sensitive content pattern matching",
        "target_sections": redactor.target_sections[:5],  # Show first 5
        "sensitive_patterns_count": len(redactor.sensitive_content_patterns)
    }

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "service": "pdf-enhanced-sensitive-content-redactor",
        "version": "5.0.1"
    }

@app.get("/sensitive-patterns")
def get_sensitive_patterns():
    """Get list of sensitive content regex patterns"""
    return {
        "count": len(redactor.sensitive_content_patterns),
        "patterns": redactor.sensitive_content_patterns
    }

@app.get("/sections")
def get_sections():
    """Get list of section headers targeted for redaction"""
    return {
        "count": len(redactor.target_sections),
        "sections": redactor.target_sections,
        "major_section_headers": redactor.major_section_headers
    }

@app.post("/redact-pdf")
async def redact_pdf(file: UploadFile = File(...), debug: bool = False):
    """
    Upload a PDF for redaction.
    - Redacts sensitive medical sections
    - Detects and redacts sensitive content (mental health, substance abuse, HIV/STD, abuse, genetics, reproductive health, etc.)
    - FIXED: No longer redacts ED Provider Notes
    """
    try:
        if not file.filename.lower().endswith(".pdf"):
            raise HTTPException(status_code=400, detail="Only PDF files are supported")

        pdf_bytes = await file.read()
        redacted_pdf = redactor.redact_pdf(pdf_bytes, debug_mode=debug)

        return Response(
            content=redacted_pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=redacted_{file.filename}"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Redaction failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Redaction failed: {str(e)}")
