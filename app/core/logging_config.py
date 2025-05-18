import logging
import sys
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    """
    formatter that outputs JSON strings after parsing the log record.
    """
    
    def format(self, record):
        logobj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
        }
        
        if hasattr(record, 'request_id'):
            logobj['request_id'] = record.request_id
            
        if record.exc_info:
            logobj['exception'] = self.formatException(record.exc_info)
            
        # converts to json string
        return json.dumps(logobj)
    
    def setup_logging(log_level="INFO"):
        """configure logging for the application."""
        
        # convert string log level to numeric value
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            numeric_level = logging.INFO
        
        # root logger configuration
        root_logger = logging.getLogger()
        root_logger.setLevel(numeric_level)
        
        # remove existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # console handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        root_logger.addHandler(handler)
        
        # set lower level for uvicorn.access to avoid double-logging
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        
        return root_logger