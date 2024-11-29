import logging
import json
import os
import socket
from datetime import datetime

# Custom Log Formatter to produce logs in the required JSON format
class JSONLogFormatter(logging.Formatter):
    def format(self, record):
        # Add the extra data (if any) from the record.extra
        additional_data = {
            "eventSource": "Application",  # Static or dynamic source
            "eventID": getattr(record, 'eventID', 'Unknown')  # Event ID, passed dynamically
        }

        # Incorporate any dynamic extra data into additionalData
        if hasattr(record, 'extraData'):
            additional_data.update(record.extraData)

        # Construct the final log record in JSON format
        log_record = {
            "pri": 34,  # Example priority, modify as per your needs
            "version": 1,  # Log version
            "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),  # Timestamp in UTC
            "hostname": socket.gethostname(),  # Get the hostname of the machine
            "serviceName": "MyFlaskMicroservice",  # Your service name
            "processId": os.getpid(),  # Process ID of the running application
            "messageId": f"ID{record.msecs}",  # Use milliseconds part of timestamp as ID
            "logLevel": record.levelname,  # Log level (DEBUG, INFO, ERROR, etc.)
            "additionalData": additional_data,  # Add the dynamic additional data here
            "message": record.getMessage()  # The actual log message
        }
        return json.dumps(log_record)  # Return the log in JSON format

# Function to set up logger with custom JSON formatting
def setup_logger(name, log_file, level, console_output=True):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Create a formatter and attach it to handlers
    formatter = JSONLogFormatter()

    # Create and add a FileHandler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Optionally, create and add a StreamHandler for console output
    if console_output:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(level)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    return logger
