#!/usr/bin/env python3
"""
Instamart GRN Scheduler - Runs workflows every 3 hours and logs to Google Sheets
"""

import os
import json
import base64
import tempfile
import time
import logging
import schedule
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
import re
import warnings

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
import io

# Add LlamaParse import
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False
    print("WARNING: LlamaParse not available. Install with: pip install llama-cloud-services")

warnings.filterwarnings("ignore")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('instamart_scheduler.log'),
        logging.StreamHandler()
    ]
)

# Hardcoded configuration
CONFIG = {
    'mail': {
        'gdrive_folder_id': '141D679nCRsj3HM9wKhVWyxO9ni7-B6Ws',
        'sender': '',
        'search_term': 'grn & purchase return',
        'attachment_filter': 'GRN',
        'days_back': 2,
        'max_results': 500
    },
    'sheet': {
        'llama_api_key': 'llx-csECp5RB25AeiLp57MQ8GnpViLFNyaezTOoHQIiwD7yn0CMr',
        'llama_agent': 'Instamart Agent',
        'drive_folder_id': '19basSTaOUB-X0FlrwmBkeVULgE8nBQ5x',
        'spreadsheet_id': '16WLcJKfkSLkTj1io962aSkgTGbk09PMdJTgkWNn11fw',
        'sheet_range': 'instamartgrn',
        'days_back': 2,
        'max_files': 500
    },
    'workflow_log': {
        'spreadsheet_id': '16WLcJKfkSLkTj1io962aSkgTGbk09PMdJTgkWNn11fw',
        'sheet_range': 'workflow_logs'
    },
    'credentials_path': 'credentials.json',
    'token_path': 'token.json'
}


class InstamartAutomation:
    def __init__(self):
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None
        
        # API scopes
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
    
    def log(self, message: str, level: str = "INFO"):
        """Log message with appropriate level"""
        if level.upper() == "ERROR":
            logging.error(message)
        elif level.upper() == "WARNING":
            logging.warning(message)
        else:
            logging.info(message)
    
    def authenticate(self):
        """Authenticate using local credentials file"""
        try:
            self.log("Starting authentication process...", "INFO")
            
            creds = None
            combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
            
            # Load token if exists
            if os.path.exists(CONFIG['token_path']):
                creds = Credentials.from_authorized_user_file(CONFIG['token_path'], combined_scopes)
            
            # Refresh or get new credentials
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    self.log("Refreshing expired token...", "INFO")
                    creds.refresh(Request())
                else:
                    if not os.path.exists(CONFIG['credentials_path']):
                        self.log(f"Credentials file not found: {CONFIG['credentials_path']}", "ERROR")
                        return False
                    
                    self.log("Starting new OAuth flow...", "INFO")
                    flow = InstalledAppFlow.from_client_secrets_file(
                        CONFIG['credentials_path'], combined_scopes)
                    creds = flow.run_local_server(port=0)
                
                # Save credentials
                with open(CONFIG['token_path'], 'w') as token:
                    token.write(creds.to_json())
                self.log("Token saved successfully", "INFO")
            
            # Build services
            self.gmail_service = build('gmail', 'v1', credentials=creds)
            self.drive_service = build('drive', 'v3', credentials=creds)
            self.sheets_service = build('sheets', 'v4', credentials=creds)
            
            self.log("Authentication successful!", "INFO")
            return True
            
        except Exception as e:
            self.log(f"Authentication failed: {str(e)}", "ERROR")
            return False
    
    def search_emails(self, sender: str = "", search_term: str = "", 
                     days_back: int = 7, max_results: int = 50) -> List[Dict]:
        """Search for emails with attachments"""
        try:
            query_parts = ["has:attachment"]
            
            if sender:
                query_parts.append(f'from:"{sender}"')  
            
            if search_term:
                if "," in search_term:
                    keywords = [k.strip() for k in search_term.split(",")]
                    keyword_query = " OR ".join([f'"{k}"' for k in keywords if k])
                    if keyword_query:
                        query_parts.append(f"({keyword_query})")
                else:
                    query_parts.append(f'"{search_term}"')
            
            start_date = datetime.now() - timedelta(days=days_back)
            query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
            
            query = " ".join(query_parts)
            self.log(f"[SEARCH] Searching Gmail with query: {query}")
            
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            self.log(f"[SEARCH] Found {len(messages)} emails matching criteria")
            
            return messages
            
        except Exception as e:
            self.log(f"[ERROR] Email search failed: {str(e)}")
            return []
    
    def get_email_details(self, message_id: str) -> Dict:
        """Get email details including sender and subject"""
        try:
            message = self.gmail_service.users().messages().get(
                userId='me', id=message_id, format='metadata'
            ).execute()
            
            headers = message['payload'].get('headers', [])
            
            details = {
                'id': message_id,
                'sender': next((h['value'] for h in headers if h['name'] == "From"), "Unknown"),
                'subject': next((h['value'] for h in headers if h['name'] == "Subject"), "(No Subject)"),
                'date': next((h['value'] for h in headers if h['name'] == "Date"), "")
            }
            
            return details
            
        except Exception as e:
            self.log(f"[ERROR] Failed to get email details for {message_id}: {str(e)}")
            return {}
    
    def sanitize_filename(self, filename: str) -> str:
        """Clean up filenames to be safe for all operating systems"""
        cleaned = re.sub(r'[<>:"/\\|?*]', '_', filename)
        if len(cleaned) > 100:
            name_parts = cleaned.split('.')
            if len(name_parts) > 1:
                extension = name_parts[-1]
                base_name = '.'.join(name_parts[:-1])
                cleaned = f"{base_name[:95]}.{extension}"
            else:
                cleaned = cleaned[:100]
        return cleaned
    
    def classify_extension(self, filename: str) -> str:
        """Categorize file by extension"""
        if not filename or '.' not in filename:
            return "Other"
            
        ext = filename.split(".")[-1].lower()
        
        type_map = {
            "pdf": "PDFs",
            "doc": "Documents", "docx": "Documents", "txt": "Documents",
            "xls": "Spreadsheets", "xlsx": "Spreadsheets", "csv": "Spreadsheets",
            "jpg": "Images", "jpeg": "Images", "png": "Images", "gif": "Images",
            "ppt": "Presentations", "pptx": "Presentations",
            "zip": "Archives", "rar": "Archives", "7z": "Archives",
        }
        
        return type_map.get(ext, "Other")
    
    def create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None) -> str:
        """Create a folder in Google Drive"""
        try:
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"
            
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                folder_id = files[0]['id']
                self.log(f"[DRIVE] Using existing folder: {folder_name} (ID: {folder_id})")
                return folder_id
            
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            if parent_folder_id:
                folder_metadata['parents'] = [parent_folder_id]
            
            folder = self.drive_service.files().create(
                body=folder_metadata,
                fields='id'
            ).execute()
            
            folder_id = folder.get('id')
            self.log(f"[DRIVE] Created Google Drive folder: {folder_name} (ID: {folder_id})")
            
            return folder_id
            
        except Exception as e:
            self.log(f"[ERROR] Failed to create folder {folder_name}: {str(e)}")
            return ""
    
    def upload_to_drive(self, file_data: bytes, filename: str, folder_id: str) -> bool:
        """Upload file to Google Drive"""
        try:
            query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                self.log(f"[DRIVE] File already exists, skipping: {filename}")
                return True
            
            file_metadata = {
                'name': filename,
                'parents': [folder_id] if folder_id else []
            }
            
            media = MediaIoBaseUpload(
                io.BytesIO(file_data),
                mimetype='application/octet-stream',
                resumable=True
            )
            
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            self.log(f"[DRIVE] Uploaded to Drive: {filename}")
            return True
            
        except Exception as e:
            self.log(f"[ERROR] Failed to upload {filename}: {str(e)}")
            return False
    
    def process_attachment(self, message_id: str, part: Dict, sender_info: Dict, 
                          search_term: str, base_folder_id: str, attachment_filter: str) -> bool:
        """Process and upload a single attachment"""
        try:
            filename = part.get("filename", "")
            if not filename:
                return False
            
            if attachment_filter and attachment_filter.lower() not in filename.lower():
                self.log(f"[SKIPPED] Attachment {filename} does not contain '{attachment_filter}'")
                return False
            
            clean_filename = self.sanitize_filename(filename)
            final_filename = clean_filename

            attachment_id = part["body"].get("attachmentId")
            if not attachment_id:
                return False
            
            att = self.gmail_service.users().messages().attachments().get(
                userId='me', messageId=message_id, id=attachment_id
            ).execute()
            
            if not att.get("data"):
                return False
            
            file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
            
            search_folder_name = search_term if search_term else "all-attachments"
            file_type_folder = self.classify_extension(filename)
            
            search_folder_id = self.create_drive_folder(search_folder_name, base_folder_id)
            type_folder_id = self.create_drive_folder(file_type_folder, search_folder_id)
            
            success = self.upload_to_drive(file_data, final_filename, type_folder_id)
            
            if success:
                self.log(f"[SUCCESS] Processed attachment: {filename}")
            
            return success
            
        except Exception as e:
            self.log(f"[ERROR] Failed to process attachment {part.get('filename', 'unknown')}: {str(e)}")
            return False
    
    def extract_attachments_from_email(self, message_id: str, payload: Dict, 
                                     sender_info: Dict, search_term: str, 
                                     base_folder_id: str, attachment_filter: str) -> int:
        """Recursively extract all attachments from an email"""
        processed_count = 0
        
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self.extract_attachments_from_email(
                    message_id, part, sender_info, search_term, base_folder_id, attachment_filter
                )
        
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            if self.process_attachment(message_id, payload, sender_info, search_term, base_folder_id, attachment_filter):
                processed_count += 1
        
        return processed_count
    
    def process_mail_to_drive_workflow(self, config: dict):
        """Process Mail to Drive workflow"""
        try:
            self.log("[START] Starting Gmail to Google Drive automation")
            
            emails = self.search_emails(
                sender=config['sender'],
                search_term=config['search_term'],
                days_back=config['days_back'],
                max_results=config['max_results']
            )
            
            if not emails:
                self.log("[INFO] No emails found matching criteria")
                return {'success': True, 'processed': 0, 'total_attachments': 0, 'failed': 0}
            
            base_folder_name = f"Gmail_Attachments"
            base_folder_id = self.create_drive_folder(base_folder_name, config.get('gdrive_folder_id'))
            if not base_folder_id:
                self.log("[ERROR] Failed to create base folder in Google Drive")
                return {'success': False, 'processed': 0, 'total_attachments': 0, 'failed': 0}
            
            stats = {
                'total_emails': len(emails),
                'processed_emails': 0,
                'total_attachments': 0,
                'successful_uploads': 0,
                'failed_uploads': 0
            }
            
            self.log(f"[PROCESS] Processing {len(emails)} emails...")
            
            for i, email in enumerate(emails, 1):
                try:
                    sender_info = self.get_email_details(email['id'])
                    if not sender_info:
                        continue
                    
                    message = self.gmail_service.users().messages().get(
                        userId='me', id=email['id']
                    ).execute()
                    
                    if not message or not message.get('payload'):
                        continue
                    
                    attachment_count = self.extract_attachments_from_email(
                        email['id'], message['payload'], sender_info, config['search_term'], base_folder_id, config['attachment_filter']
                    )
                    
                    stats['total_attachments'] += attachment_count
                    stats['successful_uploads'] += attachment_count
                    stats['processed_emails'] += 1
                    
                    subject = sender_info.get('subject', 'No Subject')[:50]
                    self.log(f"[PROCESS] Found {attachment_count} attachments in email: {subject}")
                    
                except Exception as e:
                    self.log(f"[ERROR] Failed to process email {email.get('id', 'unknown')}: {str(e)}")
                    stats['failed_uploads'] += 1
            
            self.log("[COMPLETE] Mail to Drive workflow complete!")
            self.log(f"[STATS] Emails processed: {stats['processed_emails']}/{stats['total_emails']}")
            self.log(f"[STATS] Total attachments: {stats['total_attachments']}")
            self.log(f"[STATS] Successful uploads: {stats['successful_uploads']}")
            self.log(f"[STATS] Failed uploads: {stats['failed_uploads']}")
            
            return {
                'success': True, 
                'processed': stats['processed_emails'], 
                'total_attachments': stats['successful_uploads'],
                'failed': stats['failed_uploads']
            }
            
        except Exception as e:
            self.log(f"Mail to Drive workflow failed: {str(e)}", "ERROR")
            return {'success': False, 'processed': 0, 'total_attachments': 0, 'failed': 0}
    
    def list_drive_files(self, folder_id: str, days_back: int = 1) -> List[Dict]:
        """List all PDF files in a Google Drive folder filtered by creation date"""
        try:
            start_datetime = datetime.utcnow() - timedelta(days=days_back - 1)
            start_str = start_datetime.strftime('%Y-%m-%dT00:00:00Z')
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false and createdTime >= '{start_str}'"
            
            files = []
            page_token = None

            while True:
                results = self.drive_service.files().list(
                    q=query,
                    fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime)",
                    orderBy="createdTime desc",
                    pageToken=page_token,
                    pageSize=100
                ).execute()
                
                files.extend(results.get('files', []))
                page_token = results.get('nextPageToken', None)
                
                if page_token is None:
                    break

            self.log(f"[DRIVE] Found {len(files)} PDF files in folder {folder_id} (last {days_back} days)")
            
            return files
        except Exception as e:
            self.log(f"[ERROR] Failed to list files in folder {folder_id}: {str(e)}")
            return []
    
    def download_from_drive(self, file_id: str, file_name: str) -> bytes:
        """Download a file from Google Drive"""
        try:
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            return file_data
        except Exception as e:
            self.log(f"[ERROR] Failed to download file {file_name}: {str(e)}")
            return b""
    
    def append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]]) -> bool:
        """Append data to a Google Sheet with retry mechanism"""
        max_retries = 3
        wait_time = 2
        
        for attempt in range(1, max_retries + 1):
            try:
                body = {'values': values}
                result = self.sheets_service.spreadsheets().values().append(
                    spreadsheetId=spreadsheet_id, 
                    range=range_name,
                    valueInputOption='USER_ENTERED', 
                    body=body
                ).execute()
                
                updated_cells = result.get('updates', {}).get('updatedCells', 0)
                self.log(f"[SHEETS] Appended {updated_cells} cells to Google Sheet")
                return True
            except Exception as e:
                if attempt < max_retries:
                    self.log(f"[SHEETS] Attempt {attempt} failed: {str(e)}")
                    time.sleep(wait_time)
                else:
                    self.log(f"[ERROR] Failed to append to Google Sheet: {str(e)}")
                    return False
        return False
    
    def get_sheet_headers(self, spreadsheet_id: str, sheet_name: str) -> List[str]:
        """Get existing headers from Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:Z1",
                majorDimension="ROWS"
            ).execute()
            values = result.get('values', [])
            return values[0] if values else []
        except Exception as e:
            self.log(f"[SHEETS] No existing headers or error: {str(e)}")
            return []
    
    def get_value(self, data, possible_keys, default=""):
        """Return the first found key value from dict."""
        for key in possible_keys:
            if key in data:
                return data[key]
        return default
    
    def safe_extract(self, agent, file_path: str, retries: int = 3, wait_time: int = 2):
        """Retry-safe extraction to handle server disconnections"""
        for attempt in range(1, retries + 1):
            try:
                result = agent.extract(file_path)
                return result
            except Exception as e:
                self.log(f"Attempt {attempt} failed for {file_path}: {e}")
                time.sleep(wait_time)
        raise Exception(f"Extraction failed after {retries} attempts for {file_path}")
    
    def process_extracted_data(self, extracted_data: Dict, file_info: Dict) -> List[Dict]:
        """Process extracted data to match the specified JSON structure"""
        rows = []
        items = []
        
        # Try multiple possible keys for items
        item_key_found = None
        for possible_key in ["items", "product_items", "line_items", "products", "grn_items"]:
            if possible_key in extracted_data:
                items = extracted_data.get(possible_key, [])
                item_key_found = possible_key
                break
        
        if not items:
            self.log(f"[WARNING] No items found in {file_info['name']}. Keys available: {list(extracted_data.keys())}")
            return rows
        
        self.log(f"[DEBUG] Processing {len(items)} items from key '{item_key_found}' in {file_info['name']}")
        
        # Extract base document-level information
        row_base = {
            "vendor_name": self.get_value(extracted_data, ["vendor_name", "supplier", "vendor", "Supplier Name"]),
            "po_number": self.get_value(extracted_data, ["po_number", "purchase_order_number", "PO No"]),
            "po_date": self.get_value(extracted_data, ["po_date", "purchase_order_date"]),
            "grn_no": self.get_value(extracted_data, ["grn_no", "grn_number"]),
            "grn_date": self.get_value(extracted_data, ["grn_date", "delivered_on", "GRN Date"]),
            "invoice_no": self.get_value(extracted_data, ["invoice_no", "vendor_invoice_number", "invoice_number", "inv_no", "Invoice No"]),
            "invoice_date": self.get_value(extracted_data, ["invoice_date", "invoice_dt"]),
            "source_file": file_info['name'],
            "processed_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "drive_file_id": file_info['id']
        }
        
        # Process each item
        for item_idx, item in enumerate(items):
            if not isinstance(item, dict):
                self.log(f"[WARNING] Item {item_idx} is not a dict, skipping")
                continue
                
            row = row_base.copy()
            row.update({
                "sku_code": self.get_value(item, ["sku_code", "sku", "product_code"]),
                "sku_description": self.get_value(item, ["sku_description", "description", "product_name", "item_description"]),
                "vendor_sku": self.get_value(item, ["vendor_sku", "vendor_sku_code"]),
                "sku_bin": self.get_value(item, ["sku_bin", "bin_code"]),
                "lot_no": self.get_value(item, ["lot_no", "lot_number", "batch_no"]),
                "lot_mrp": self.get_value(item, ["lot_mrp", "mrp"]),
                "exp_qty": self.get_value(item, ["exp_qty", "expected_quantity", "ordered_qty"]),
                "recv_qty": self.get_value(item, ["recv_qty", "received_quantity", "qty"]),
                "unit_price": self.get_value(item, ["unit_price", "price_per_unit", "rate"]),
                "taxable_value": self.get_value(item, ["taxable_value", "taxable_amt"]),
                "add_cess": self.get_value(item, ["add_cess", "additional_cess"]),
                "total_inr": self.get_value(item, ["total_inr", "total_amount", "amount"])
            })
            
            # Only keep non-empty values
            cleaned_row = {k: v for k, v in row.items() if v not in ["", None]}
            rows.append(cleaned_row)
        
        self.log(f"[DEBUG] Created {len(rows)} rows from {len(items)} items")
        return rows

    def debug_extraction_structure(self, extraction_result, filename: str):
        """Debug helper to understand extraction structure"""
        self.log(f"[DEBUG] ===== EXTRACTION STRUCTURE FOR {filename} =====")
        
        def log_structure(obj, indent=0):
            prefix = "  " * indent
            if isinstance(obj, list):
                self.log(f"{prefix}List with {len(obj)} items")
                if obj:
                    log_structure(obj[0], indent + 1)
            elif isinstance(obj, dict):
                self.log(f"{prefix}Dict with keys: {list(obj.keys())}")
                for key in ["items", "product_items", "line_items"]:
                    if key in obj:
                        self.log(f"{prefix}  -> {key}: {len(obj[key])} items")
            elif hasattr(obj, 'data'):
                self.log(f"{prefix}Object with .data attribute")
                log_structure(obj.data, indent + 1)
            else:
                self.log(f"{prefix}Type: {type(obj)}")
        
        log_structure(extraction_result)
        self.log(f"[DEBUG] ===== END STRUCTURE =====")
    
    def get_existing_source_files(self, spreadsheet_id: str, sheet_range: str) -> set:
        """Get set of existing source_file from Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_range,
                majorDimension="ROWS"
            ).execute()
            
            values = result.get('values', [])
            if not values:
                return set()
            
            headers = values[0]
            if "source_file" not in headers:
                self.log("No 'source_file' column found in sheet", "WARNING")
                return set()
            
            name_index = headers.index("source_file")
            existing_names = {row[name_index] for row in values[1:] if len(row) > name_index and row[name_index]}
            
            self.log(f"Found {len(existing_names)} existing file names in sheet", "INFO")
            return existing_names
            
        except Exception as e:
            self.log(f"Failed to get existing file names: {str(e)}", "ERROR")
            return set()
    
    def update_headers(self, spreadsheet_id: str, sheet_name: str, new_headers: List[str]) -> bool:
        """Update the header row with new columns"""
        try:
            body = {'values': [new_headers]}
            result = self.sheets_service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:{chr(64 + len(new_headers))}1",
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
            self.log(f"Updated headers with {len(new_headers)} columns")
            return True
        except Exception as e:
            self.log(f"[ERROR] Failed to update headers: {str(e)}")
            return False
    
    def process_drive_to_sheet_workflow(self, config: dict, skip_existing: bool = True):
        """Process Drive to Sheet workflow"""
        stats = {
            'total_pdfs': 0,
            'processed_pdfs': 0,
            'failed_pdfs': 0,
            'skipped_pdfs': 0,
            'rows_added': 0
        }
        
        if not LLAMA_AVAILABLE:
            self.log("[ERROR] LlamaParse not available. Install with: pip install llama-cloud-services")
            return stats
        
        try:
            self.log("Starting Drive to Sheet workflow with LlamaParse", "INFO")
            
            os.environ["LLAMA_CLOUD_API_KEY"] = config['llama_api_key']
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=config['llama_agent'])
            
            if agent is None:
                self.log(f"[ERROR] Could not find agent '{config['llama_agent']}'. Check dashboard.")
                return stats
            
            self.log("LlamaParse agent found")
            
            sheet_name = config['sheet_range'].split('!')[0]
            
            existing_names = set()
            if skip_existing:
                existing_names = self.get_existing_source_files(config['spreadsheet_id'], config['sheet_range'])
                self.log(f"Skipping {len(existing_names)} already processed files", "INFO")
            
            pdf_files = self.list_drive_files(config['drive_folder_id'], config.get('days_back', 7))
            stats['total_pdfs'] = len(pdf_files)
            
            if skip_existing:
                original_count = len(pdf_files)
                pdf_files = [f for f in pdf_files if f['name'] not in existing_names]
                stats['skipped_pdfs'] = original_count - len(pdf_files)
                self.log(f"After filtering, {len(pdf_files)} PDFs to process", "INFO")
            
            max_files = config.get('max_files')
            if max_files is not None:
                pdf_files = pdf_files[:max_files]
                self.log(f"Limited to {len(pdf_files)} PDFs after max_files limit", "INFO")
            
            if not pdf_files:
                self.log("[INFO] No PDF files found to process")
                return stats
            
            self.log(f"Found {len(pdf_files)} PDF files to process")
            
            headers = self.get_sheet_headers(config['spreadsheet_id'], sheet_name)
            headers_set = False

            for pdf_file in pdf_files:
                try:
                    self.log(f"Processing: {pdf_file['name']}")
                    
                    file_data = self.download_from_drive(pdf_file['id'], pdf_file['name'])
                    if not file_data:
                        self.log(f"[ERROR] Failed to download {pdf_file['name']}")
                        stats['failed_pdfs'] += 1
                        continue
                    
                    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_file:
                        tmp_file.write(file_data)
                        tmp_path = tmp_file.name
                    
                    try:
                        extraction_result = self.safe_extract(agent, tmp_path)
                        self.debug_extraction_structure(extraction_result, pdf_file['name'])
                        
                        # Enhanced debug logging
                        self.log(f"[DEBUG] Extraction result type: {type(extraction_result)}")
                        
                        # Handle different return formats from LlamaExtract
                        all_extracted_data = []
                        
                        if isinstance(extraction_result, list):
                            self.log(f"[DEBUG] Received list with {len(extraction_result)} result objects")
                            for idx, r in enumerate(extraction_result):
                                if hasattr(r, 'data'):
                                    all_extracted_data.append(r.data)
                                    self.log(f"[DEBUG] Result {idx}: extracted .data attribute")
                                elif isinstance(r, dict):
                                    all_extracted_data.append(r)
                                    self.log(f"[DEBUG] Result {idx}: is dict")
                                else:
                                    all_extracted_data.append(r)
                                    self.log(f"[DEBUG] Result {idx}: type {type(r)}")
                        else:
                            if hasattr(extraction_result, 'data'):
                                all_extracted_data = [extraction_result.data]
                                self.log(f"[DEBUG] Single result: extracted .data attribute")
                            elif isinstance(extraction_result, dict):
                                all_extracted_data = [extraction_result]
                                self.log(f"[DEBUG] Single result: is dict")
                            else:
                                all_extracted_data = [extraction_result]
                                self.log(f"[DEBUG] Single result: type {type(extraction_result)}")
                        
                        # Process all pages/chunks and accumulate rows
                        rows_data = []
                        total_items_found = 0
                        
                        for page_idx, extracted_data in enumerate(all_extracted_data):
                            self.log(f"[DEBUG] Processing chunk {page_idx + 1}/{len(all_extracted_data)}")
                            
                            if isinstance(extracted_data, dict):
                                # Log available keys for debugging
                                self.log(f"[DEBUG] Available keys: {list(extracted_data.keys())}")
                                
                                # Count items before processing
                                items_in_chunk = 0
                                for possible_key in ["items", "product_items", "line_items", "products"]:
                                    if possible_key in extracted_data:
                                        items_in_chunk = len(extracted_data[possible_key])
                                        self.log(f"[DEBUG] Found {items_in_chunk} items in key '{possible_key}'")
                                        break
                                
                                total_items_found += items_in_chunk
                                
                                # Process this chunk
                                chunk_rows = self.process_extracted_data(extracted_data, pdf_file)
                                rows_data.extend(chunk_rows)
                                self.log(f"[DEBUG] Chunk {page_idx + 1} produced {len(chunk_rows)} rows")
                            else:
                                self.log(f"[WARNING] Chunk {page_idx + 1} is not a dict: {type(extracted_data)}")
                        
                        self.log(f"[INFO] Total items found: {total_items_found}, Total rows created: {len(rows_data)}")
                        
                        if not rows_data:
                            self.log(f"[SKIP] No items found in {pdf_file['name']}")
                            stats['failed_pdfs'] += 1
                            continue
                        
                        if not headers_set:
                            all_keys = set()
                            for row in rows_data:
                                all_keys.update(row.keys())
                            
                            new_headers = sorted(list(all_keys))
                            
                            if headers:
                                combined = list(dict.fromkeys(headers + new_headers))
                                if combined != headers:
                                    self.update_headers(config['spreadsheet_id'], sheet_name, combined)
                                    headers = combined
                            else:
                                self.update_headers(config['spreadsheet_id'], sheet_name, new_headers)
                                headers = new_headers
                            
                            headers_set = True
                        
                        sheet_rows = []
                        for row_dict in rows_data:
                            row_values = [row_dict.get(h, "") for h in headers]
                            sheet_rows.append(row_values)
                        
                        if self.append_to_google_sheet(config['spreadsheet_id'], config['sheet_range'], sheet_rows):
                            stats['rows_added'] += len(sheet_rows)
                            stats['processed_pdfs'] += 1
                            self.log(f"[SUCCESS] Processed {pdf_file['name']}: {len(sheet_rows)} rows added")
                        else:
                            stats['failed_pdfs'] += 1
                            self.log(f"[ERROR] Failed to append data for {pdf_file['name']}")
                    
                    finally:
                        if os.path.exists(tmp_path):
                            os.remove(tmp_path)
                
                except Exception as e:
                    self.log(f"[ERROR] Failed to process {pdf_file.get('name', 'unknown')}: {str(e)}")
                    stats['failed_pdfs'] += 1
            
            self.log("[COMPLETE] Drive to Sheet workflow complete!")
            self.log(f"[STATS] PDFs processed: {stats['processed_pdfs']}/{stats['total_pdfs']}")
            self.log(f"[STATS] PDFs skipped: {stats['skipped_pdfs']}")
            self.log(f"[STATS] PDFs failed: {stats['failed_pdfs']}")
            self.log(f"[STATS] Total rows added: {stats['rows_added']}")
            
            return stats
            
        except Exception as e:
            self.log(f"Drive to Sheet workflow failed: {str(e)}", "ERROR")
            return stats
    
    def log_workflow_to_sheet(self, workflow_name: str, start_time: datetime, 
                             end_time: datetime, stats: dict):
        """Log workflow execution details to Google Sheet"""
        try:
            duration = (end_time - start_time).total_seconds()
            duration_str = f"{duration:.2f}s"
            
            if duration >= 60:
                minutes = int(duration // 60)
                seconds = int(duration % 60)
                duration_str = f"{minutes}m {seconds}s"
            
            log_row = [
                start_time.strftime("%Y-%m-%d %H:%M:%S"),
                end_time.strftime("%Y-%m-%d %H:%M:%S"),
                duration_str,
                workflow_name,
                stats.get('processed', stats.get('processed_pdfs', 0)),
                stats.get('total_attachments', stats.get('rows_added', 0)),
                stats.get('failed', stats.get('failed_pdfs', 0)),
                stats.get('skipped_pdfs', 0),
                "Success" if stats.get('success', stats.get('processed_pdfs', 0) > 0) else "Failed"
            ]
            
            log_config = CONFIG['workflow_log']
            
            headers = self.get_sheet_headers(log_config['spreadsheet_id'], log_config['sheet_range'])
            if not headers:
                header_row = [
                    "Start Time", "End Time", "Duration", "Workflow", 
                    "Processed", "Total Items", "Failed", "Skipped", "Status"
                ]
                self.append_to_google_sheet(
                    log_config['spreadsheet_id'], 
                    log_config['sheet_range'], 
                    [header_row]
                )
            
            self.append_to_google_sheet(
                log_config['spreadsheet_id'],
                log_config['sheet_range'],
                [log_row]
            )
            
            self.log(f"[WORKFLOW LOG] Logged workflow: {workflow_name}")
            
        except Exception as e:
            self.log(f"[ERROR] Failed to log workflow: {str(e)}")
    
    def run_scheduled_workflow(self):
        """Run both workflows in sequence and log results"""
        try:
            self.log("=" * 80)
            self.log("STARTING SCHEDULED WORKFLOW RUN")
            self.log("=" * 80)
            
            overall_start = datetime.now(timezone.utc)
            
            # Workflow 1: Mail to Drive
            self.log("\n[WORKFLOW 1/2] Starting Mail to Drive workflow...")
            mail_start = datetime.now(timezone.utc)
            mail_stats = self.process_mail_to_drive_workflow(CONFIG['mail'])
            mail_end = datetime.now(timezone.utc)
            self.log_workflow_to_sheet("Mail to Drive", mail_start, mail_end, mail_stats)
            
            # Small delay between workflows
            time.sleep(5)
            
            # Workflow 2: Drive to Sheet
            self.log("\n[WORKFLOW 2/2] Starting Drive to Sheet workflow...")
            sheet_start = datetime.now(timezone.utc)
            sheet_stats = self.process_drive_to_sheet_workflow(CONFIG['sheet'], skip_existing=True)
            sheet_end = datetime.now(timezone.utc)
            
            sheet_stats_for_log = {
                'processed_pdfs': sheet_stats['processed_pdfs'],
                'rows_added': sheet_stats['rows_added'],
                'failed_pdfs': sheet_stats['failed_pdfs'],
                'skipped_pdfs': sheet_stats['skipped_pdfs'],
                'success': sheet_stats['processed_pdfs'] > 0
            }
            self.log_workflow_to_sheet("Drive to Sheet", sheet_start, sheet_end, sheet_stats_for_log)
            
            overall_end = datetime.now(timezone.utc)
            total_duration = (overall_end - overall_start).total_seconds()
            
            self.log("\n" + "=" * 80)
            self.log("SCHEDULED WORKFLOW RUN COMPLETED")
            self.log(f"Total Duration: {total_duration:.2f} seconds")
            self.log(f"Mail to Drive: {mail_stats['processed']} emails, {mail_stats['total_attachments']} attachments")
            self.log(f"Drive to Sheet: {sheet_stats['processed_pdfs']} PDFs processed, {sheet_stats['rows_added']} rows added")
            self.log("=" * 80 + "\n")
            
        except Exception as e:
            self.log(f"[ERROR] Scheduled workflow failed: {str(e)}", "ERROR")


def main():
    """Main function to run the scheduler"""
    print("=" * 80)
    print("INSTAMART GRN SCHEDULER")
    print("Runs every 3 hours: Mail to Drive → Drive to Sheet")
    print("=" * 80)
    
    automation = InstamartAutomation()
    
    # Authenticate
    print("\nAuthenticating...")
    if not automation.authenticate():
        print("ERROR: Authentication failed. Please check credentials.")
        return
    
    print("Authentication successful!")
    
    # Run immediately on start
    print("\nRunning initial workflow...")
    automation.run_scheduled_workflow()
    
    # Schedule to run every 3 hours
    schedule.every(3).hours.do(automation.run_scheduled_workflow)
    
    print(f"\nScheduler started. Next run in 3 hours.")
    print(f"Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Press Ctrl+C to stop the scheduler\n")
    
    # Keep running
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    except KeyboardInterrupt:
        print("\n\nScheduler stopped by user.")
        print("=" * 80)


if __name__ == "__main__":
    main()