"""
OCR adapter for extracting text from images and PDFs.

Uses tesseract for OCR operations when available.
"""

import tempfile
from pathlib import Path
from typing import List, Optional

from boxi.config import get_settings
from boxi.logging_config import get_logger, log_tool_missing
from boxi.utils.process import ProcessError, ProcessTimeout, run

logger = get_logger(__name__)


class OCRAdapter:
    """Adapter for OCR operations using tesseract."""
    
    def __init__(self):
        self.settings = get_settings()
        self.tesseract_path = self.settings.get_tool_path("tesseract")
        self.timeout = self.settings.default_timeout
    
    def is_available(self) -> bool:
        """Check if tesseract is available."""
        return self.tesseract_path is not None
    
    def extract_text_from_image(self, image_path: Path) -> Optional[str]:
        """
        Extract text from an image file.
        
        Args:
            image_path: Path to image file
            
        Returns:
            Extracted text or None if failed
        """
        if not self.is_available():
            log_tool_missing("tesseract", "OCR")
            return None
        
        try:
            logger.debug(f"Extracting text from image: {image_path}")
            
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Remove .txt extension as tesseract adds it automatically
            output_base = temp_path.replace('.txt', '')
            
            cmd = [
                self.tesseract_path,
                str(image_path),
                output_base,
                '-l', 'eng',  # English language
                '--psm', '6',  # Assume uniform block of text
            ]
            
            result = run(cmd, timeout=self.timeout)
            
            # Read extracted text
            output_file = Path(f"{output_base}.txt")
            if output_file.exists():
                text = output_file.read_text(encoding='utf-8').strip()
                output_file.unlink()  # Clean up
                
                if text:
                    logger.info(f"Extracted {len(text)} characters from {image_path.name}")
                    return text
            
            return None
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"OCR extraction failed for {image_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in OCR: {e}")
            return None
    
    def extract_text_from_pdf(self, pdf_path: Path) -> Optional[str]:
        """
        Extract text from a PDF file.
        
        First tries direct text extraction, then falls back to OCR.
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            Extracted text or None if failed
        """
        # Try direct text extraction first (faster)
        text = self._extract_pdf_text_direct(pdf_path)
        if text and text.strip():
            logger.info(f"Extracted text directly from PDF: {pdf_path.name}")
            return text
        
        # Fall back to OCR
        logger.debug(f"Direct text extraction failed, trying OCR for: {pdf_path}")
        return self._extract_pdf_text_ocr(pdf_path)
    
    def _extract_pdf_text_direct(self, pdf_path: Path) -> Optional[str]:
        """Extract text directly from PDF using pdftotext if available."""
        pdftotext_path = self.settings.get_tool_path("pdftotext")
        
        if not pdftotext_path:
            return None
        
        try:
            logger.debug(f"Trying direct text extraction from PDF: {pdf_path}")
            
            cmd = [pdftotext_path, str(pdf_path), '-']  # Output to stdout
            
            result = run(cmd, timeout=self.timeout)
            
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip()
            
        except (ProcessError, ProcessTimeout) as e:
            logger.debug(f"Direct PDF text extraction failed: {e}")
        
        return None
    
    def _extract_pdf_text_ocr(self, pdf_path: Path) -> Optional[str]:
        """Extract text from PDF using OCR (convert to images first)."""
        if not self.is_available():
            return None
        
        # Check if pdftoppm is available for PDF to image conversion
        pdftoppm_path = self.settings.get_tool_path("pdftoppm")
        if not pdftoppm_path:
            logger.warning("pdftoppm not available, cannot OCR PDF")
            return None
        
        try:
            # Convert PDF to images
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Convert PDF to PNG images
                cmd = [
                    pdftoppm_path,
                    "-png",
                    "-r", "300",  # 300 DPI for better OCR
                    str(pdf_path),
                    str(temp_path / "page")
                ]
                
                logger.debug(f"Converting PDF to images: {pdf_path}")
                result = run(cmd, timeout=self.timeout * 2)
                
                if result.returncode != 0:
                    logger.error("PDF to image conversion failed")
                    return None
                
                # Find generated image files
                image_files = sorted(temp_path.glob("page-*.png"))
                
                if not image_files:
                    logger.error("No images generated from PDF")
                    return None
                
                # OCR each page and combine text
                all_text = []
                for image_file in image_files:
                    page_text = self.extract_text_from_image(image_file)
                    if page_text:
                        all_text.append(page_text)
                
                if all_text:
                    combined_text = '\n\n'.join(all_text)
                    logger.info(f"OCR extracted text from {len(image_files)} pages of {pdf_path.name}")
                    return combined_text
                
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"PDF OCR failed for {pdf_path}: {e}")
        
        return None
    
    def extract_text_from_file(self, file_path: Path) -> Optional[str]:
        """
        Extract text from a file (auto-detect type).
        
        Args:
            file_path: Path to file
            
        Returns:
            Extracted text or None if failed
        """
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return None
        
        # Determine file type by extension
        suffix = file_path.suffix.lower()
        
        if suffix == '.pdf':
            return self.extract_text_from_pdf(file_path)
        elif suffix in ['.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.gif']:
            return self.extract_text_from_image(file_path)
        elif suffix in ['.txt', '.log', '.conf', '.config']:
            # Plain text files
            try:
                return file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception as e:
                logger.error(f"Failed to read text file {file_path}: {e}")
                return None
        else:
            logger.warning(f"Unsupported file type for OCR: {suffix}")
            return None
    
    def batch_extract(self, file_paths: List[Path]) -> dict[Path, str]:
        """
        Extract text from multiple files.
        
        Args:
            file_paths: List of file paths to process
            
        Returns:
            Dictionary mapping file paths to extracted text
        """
        results = {}
        
        for file_path in file_paths:
            logger.debug(f"Processing file for OCR: {file_path}")
            text = self.extract_text_from_file(file_path)
            if text:
                results[file_path] = text
        
        logger.info(f"Successfully extracted text from {len(results)}/{len(file_paths)} files")
        return results


def create_adapter() -> OCRAdapter:
    """Create an OCR adapter instance."""
    return OCRAdapter()
