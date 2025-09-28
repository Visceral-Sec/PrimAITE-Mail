"""MIME type utilities for email attachments."""

from typing import Dict

from primaite.simulator.file_system.file_type import FileType


# Mapping of FileType to MIME types
FILE_TYPE_TO_MIME: Dict[FileType, str] = {
    # Text formats
    FileType.TXT: "text/plain",
    FileType.DOC: "application/msword",
    FileType.DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    FileType.PDF: "application/pdf",
    FileType.HTML: "text/html",
    FileType.XML: "application/xml",
    FileType.CSV: "text/csv",
    
    # Spreadsheet formats
    FileType.XLS: "application/vnd.ms-excel",
    FileType.XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    
    # Image formats
    FileType.JPEG: "image/jpeg",
    FileType.PNG: "image/png",
    FileType.GIF: "image/gif",
    FileType.BMP: "image/bmp",
    
    # Audio formats
    FileType.MP3: "audio/mpeg",
    FileType.WAV: "audio/wav",
    
    # Video formats
    FileType.MP4: "video/mp4",
    FileType.AVI: "video/x-msvideo",
    FileType.MKV: "video/x-matroska",
    FileType.FLV: "video/x-flv",
    
    # Presentation formats
    FileType.PPT: "application/vnd.ms-powerpoint",
    FileType.PPTX: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    
    # Web formats
    FileType.JS: "application/javascript",
    FileType.CSS: "text/css",
    
    # Programming languages
    FileType.PY: "text/x-python",
    FileType.C: "text/x-c",
    FileType.CPP: "text/x-c++",
    FileType.JAVA: "text/x-java",
    
    # Compressed file types
    FileType.RAR: "application/vnd.rar",
    FileType.ZIP: "application/zip",
    FileType.TAR: "application/x-tar",
    FileType.GZ: "application/gzip",
    
    # Database file types
    FileType.DB: "application/x-sqlite3",
    
    # Script file types
    FileType.PS1: "application/x-powershell",
    FileType.BAT: "application/x-msdos-program",
    FileType.SH: "application/x-sh",
    
    # Executable file types
    FileType.PE: "application/x-msdownload",
    FileType.ELF: "application/x-executable",
    
    # Unknown/default
    FileType.UNKNOWN: "application/octet-stream",
}


def get_mime_type_from_file_type(file_type: FileType) -> str:
    """
    Get MIME type from FileType.
    
    :param file_type: The FileType to convert.
    :return: MIME type string.
    """
    return FILE_TYPE_TO_MIME.get(file_type, "application/octet-stream")


def get_mime_type_from_filename(filename: str) -> str:
    """
    Get MIME type from filename extension.
    
    :param filename: The filename to analyze.
    :return: MIME type string.
    """
    if '.' not in filename:
        return "application/octet-stream"
    
    extension = filename.split('.')[-1].upper()
    
    # Handle common extension aliases
    extension_aliases = {
        'JPG': 'JPEG',
        'HTM': 'HTML',
        'TIFF': 'TIF',
        'MPEG': 'MP3',
    }
    
    extension = extension_aliases.get(extension, extension)
    
    try:
        file_type = FileType[extension]
        return get_mime_type_from_file_type(file_type)
    except KeyError:
        return "application/octet-stream"


def is_text_mime_type(mime_type: str) -> bool:
    """
    Check if a MIME type represents text content.
    
    :param mime_type: The MIME type to check.
    :return: True if it's a text MIME type.
    """
    return mime_type.startswith("text/") or mime_type in [
        "application/xml",
        "application/json",
        "application/javascript",
    ]


def is_image_mime_type(mime_type: str) -> bool:
    """
    Check if a MIME type represents image content.
    
    :param mime_type: The MIME type to check.
    :return: True if it's an image MIME type.
    """
    return mime_type.startswith("image/")


def is_executable_mime_type(mime_type: str) -> bool:
    """
    Check if a MIME type represents executable content.
    
    :param mime_type: The MIME type to check.
    :return: True if it's an executable MIME type.
    """
    executable_types = [
        "application/x-msdownload",
        "application/x-executable",
        "application/x-msdos-program",
        "application/x-sh",
        "application/x-powershell",
    ]
    return mime_type in executable_types