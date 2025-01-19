import logging
import json
import os
import syslog
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4

# Enum for Protocol
class Protocol(Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SFTP = "SFTP"
    FTPS = "FTPS"

# Enum for HTTP Methods
class Method(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"

SEVERITY_MAP = {
    "CRITICAL": syslog.LOG_CRIT,
    "ERROR": syslog.LOG_ERR,
    "WARNING": syslog.LOG_WARNING,
    "INFO": syslog.LOG_INFO,
    "DEBUG": syslog.LOG_DEBUG
}

FACILITY = syslog.LOG_USER

def calculate_pri(facility: int, severity: int) -> int:
    """
    Calculates the syslog priority value based on facility and severity levels.

    Args:
        facility: Syslog facility code.
        severity: Syslog severity code.

    Returns:
        The calculated priority (PRI) value.
    """
    return facility * 8 + severity

class RequestResponseLogFormatter(logging.Formatter):
    """
    Custom log formatter for handling WebRequest, WebResponse, and Debug events
    with structured logging compliant with RFC 5424.
    """

    def __init__(self, hostname: str, appname: str) -> None:
        """
        Initializes the formatter with hostname and application name.

        Args:
            hostname: System or host name to appear in the logs.
            appname: Application name to appear in the logs.
        """
        super().__init__()
        self.hostname = hostname
        self.appname = appname

    def format(self, record: logging.LogRecord) -> str:
        """
        Formats the log record into an RFC 5424-compatible string with a JSON payload.

        Args:
            record: The log record to format.

        Returns:
            A string containing the formatted log message.

        Raises:
            ValueError: If the record is missing mandatory fields.
        """
        # Determine syslog severity from Python log level
        severity: int = SEVERITY_MAP.get(record.levelname, syslog.LOG_NOTICE)
        pri: int = calculate_pri(FACILITY, severity)

        # RFC 5424 fixed fields
        version = 1
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + "Z"
        procid = str(os.getpid())
        msgid = getattr(record, "eventID", f"ID{int(record.msecs)}")

        # eventType is mandatory
        event_type = getattr(record, "eventType", None)
        if not event_type:
            raise ValueError("Missing mandatory field: eventType")

        # Basic structure of the JSON payload
        log_payload: Dict[str, Any] = {
            "EventType": event_type,
            "EventID": getattr(record, "eventID", "Unknown"),
            "EventReferenceID": getattr(record, "eventReferenceID", "Unknown"),
            "EventData": {}
        }

        if event_type == "WebRequest":
            self._build_web_request_payload(record, log_payload)
        elif event_type == "WebResponse":
            self._build_web_response_payload(record, log_payload)
        elif event_type == "Debug":
            self._build_debug_payload(record, log_payload)
        else:
            raise ValueError("Invalid eventType. Allowed values: 'WebRequest', 'WebResponse', 'Debug'.")

        # Construct the RFC 5424 syslog line
        syslog_line = (
            f"<{pri}>{version} {timestamp} {self.hostname} {self.appname} "
            f"{procid} {msgid} - @cee: {json.dumps(log_payload)}"
        )
        return syslog_line

    def _build_web_request_payload(self, record: logging.LogRecord, log_payload: Dict[str, Any]) -> None:
        """
        Builds the 'EventData' payload for a WebRequest event.

        Args:
            record: The log record.
            log_payload: The base payload dictionary to be updated.

        Raises:
            ValueError: If mandatory fields are missing or invalid.
        """
        protocol = getattr(record, "protocol", None)
        method = getattr(record, "method", None)
        url = getattr(record, "url", None)

        if not (protocol and method and url):
            raise ValueError("Missing mandatory fields: protocol, method, or url for WebRequest.")

        # Validate protocol
        try:
            valid_protocol = Protocol[protocol].value
        except KeyError as e:
            raise ValueError(
                f"Invalid protocol '{protocol}'. Allowed: {list(Protocol.__members__.keys())}"
            ) from e

        # Validate method
        try:
            valid_method = Method[method].value
        except KeyError as e:
            raise ValueError(
                f"Invalid method '{method}'. Allowed: {list(Method.__members__.keys())}"
            ) from e

        log_payload["EventData"] = {
            "Protocol": valid_protocol,
            "Method": valid_method,
            "Url": url,
            "Headers": getattr(record, "headers", None),
            "ClientIP": getattr(record, "clientIP", None),
            "Body": getattr(record, "body", None) if record.levelname == "DEBUG" else None
        }

    def _build_web_response_payload(self, record: logging.LogRecord, log_payload: Dict[str, Any]) -> None:
        """
        Builds the 'EventData' payload for a WebResponse event.

        Args:
            record: The log record.
            log_payload: The base payload dictionary to be updated.

        Raises:
            ValueError: If mandatory fields are missing.
        """
        protocol = getattr(record, "protocol", None)
        method = getattr(record, "method", None)
        url = getattr(record, "url", None)
        status_code = getattr(record, "statusCode", None)
        response_time = getattr(record, "responseTimeMS", None)
        client_ip = getattr(record, "clientIP", None)

        if not all([protocol, method, url, status_code, response_time, client_ip]):
            raise ValueError("Missing mandatory fields for WebResponse.")

        log_payload["EventData"] = {
            "Protocol": protocol,
            "Method": method,
            "Url": url,
            "Headers": getattr(record, "headers", {}),
            "Body": getattr(record, "body", None) if record.levelname == "DEBUG" else None,
            "StatusCode": status_code,
            "ResponseTimeMS": response_time,
            "ClientIP": client_ip
        }

    def _build_debug_payload(self, record: logging.LogRecord, log_payload: Dict[str, Any]) -> None:
        """
        Builds the 'EventData' payload for a Debug event.

        Args:
            record: The log record.
            log_payload: The base payload dictionary to be updated.
        """
        log_payload["EventData"] = {
            "Message": record.getMessage(),
            "AdditionalData": getattr(record, "additionalData", {})
        }

def setup_logger(
    name: str,
    level: int,
    request_response_log_file: Optional[str] = None,
    hostname: str = "MySystem",
    appname: str = "MyFlaskMicroservice"
) -> logging.Logger:
    """
    Configures and returns a logger with an optional file handler for
    structured request/response logs in RFC 5424 format.

    Args:
        name: Name of the logger.
        level: Logging level (e.g. logging.DEBUG, logging.INFO, etc.).
        request_response_log_file: Optional file path for the log output.
        hostname: System or host name to appear in the logs (default: 'MySystem').
        appname: Application name to appear in the logs (default: 'MyFlaskMicroservice').

    Returns:
        A configured instance of logging.Logger.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if request_response_log_file:
        handler = logging.FileHandler(request_response_log_file)
        handler.setLevel(level)
        handler.setFormatter(RequestResponseLogFormatter(hostname, appname))
        logger.addHandler(handler)

    return logger

def log_web_request(
    logger: logging.Logger,
    level: int,
    protocol: str,
    method: str,
    url: str,
    headers: Optional[Dict[str, Any]] = None,
    event_id: Optional[str] = None,
    client_ip: Optional[str] = None,
    body: Optional[Any] = None
) -> None:
    """
    Logs a WebRequest event with structured data.

    Args:
        logger: The logger instance to use.
        level: Logging level for this event (e.g. logging.INFO).
        protocol: The protocol used (e.g. 'HTTP', 'HTTPS', 'SFTP', 'FTPS').
        method: The HTTP method used (e.g. 'GET', 'POST', 'PUT', 'DELETE').
        url: The requested URL.
        headers: An optional dictionary of headers.
        event_id: A unique identifier for this event. Generated automatically if None.
        client_ip: The client IP address if applicable.
        body: The request body, only recorded at DEBUG level.
    """
    logger.log(
        level,
        "User initiated a web request",
        extra={
            "eventType": "WebRequest",
            "protocol": protocol,
            "method": method,
            "url": url,
            "headers": headers,
            "eventID": event_id or str(uuid4()),
            "eventReferenceID": str(uuid4()),
            "clientIP": client_ip,
            "body": body if level == logging.DEBUG else None
        }
    )

def log_web_response(
    logger: logging.Logger,
    level: int,
    protocol: str,
    method: str,
    url: str,
    status_code: int,
    response_time_ms: int,
    client_ip: str,
    headers: Optional[Dict[str, Any]] = None,
    body: Optional[Any] = None,
    event_reference_id: Optional[str] = None,
    event_id: Optional[str] = None
) -> None:
    """
    Logs a WebResponse event with structured data.

    Args:
        logger: The logger instance to use.
        level: Logging level for this event (e.g., logging.INFO).
        protocol: The protocol used (e.g., 'HTTP', 'HTTPS').
        method: The HTTP method used (e.g., 'GET', 'POST').
        url: The request URL.
        status_code: The HTTP status code returned.
        response_time_ms: The total response time in milliseconds.
        client_ip: The client IP address.
        headers: An optional dictionary of response headers.
        body: The response body, only logged at DEBUG level.
        event_reference_id: A unique identifier linking back to the original WebRequest.
        event_id: A unique identifier for this event. Generated automatically if None.
    """
    logger.log(
        level,
        "Web response logged successfully",
        extra={
            "eventType": "WebResponse",
            "eventID": event_id or str(uuid4()),
            "eventReferenceID": event_reference_id or str(uuid4()),
            "protocol": protocol,
            "method": method,
            "url": url,
            "headers": headers or {},
            "body": body if level == logging.DEBUG else None,
            "statusCode": status_code,
            "responseTimeMS": response_time_ms,
            "clientIP": client_ip,
        }
    )

def log_debug(
    logger: logging.Logger,
    level: int,
    message: str,
    additional_data: Optional[Dict[str, Any]] = None,
    event_id: Optional[str] = None
) -> None:
    """
    Logs a Debug event with structured data.

    Args:
        logger: The logger instance to use.
        level: Logging level for this event (typically logging.DEBUG).
        message: The debug message to log.
        additional_data: Any additional data for context, recorded in EventData.
        event_id: A unique identifier for this event. Generated automatically if None.
    """
    logger.log(
        level,
        message,
        extra={
            "eventType": "Debug",
            "additionalData": additional_data or {},
            "eventID": event_id or str(uuid4())
        }
    )
