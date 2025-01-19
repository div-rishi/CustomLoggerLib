# SDK for Structured Logging

This SDK provides tools to log structured events, including `WebRequest`, `WebResponse`, and `Debug` events, in compliance with the RFC 5424 standard. It includes facilities for defining event types, setting custom log formats, and ensuring consistency and clarity in logging across applications.

## Key Features

- **Structured Logging**: Supports RFC 5424-compliant logs with customizable fields.
- **Event Types**:
  - `WebRequest`: Logs incoming HTTP/S requests with relevant metadata.
  - `WebResponse`: Logs outgoing HTTP/S responses with additional information such as status codes and response times.
  - `Debug`: Logs debug-level information with optional additional context.
- **Customizable Protocols**: Supports `HTTP`, `HTTPS`, `SFTP`, and `FTPS` protocols.
- **Configurable Logging**: Allows customization of log file destinations, hostname, and application name.

## Usage

### Setting Up the Logger

```python
from your_module import setup_logger

# Configure the logger
logger = setup_logger(
    name="MyAppLogger",
    level=logging.DEBUG,
    request_response_log_file="app_logs.log",
    hostname="MyHost",
    appname="MyApplication"
)
```

### Logging a Web Request

```python
from your_module import log_web_request

log_web_request(
    logger=logger,
    level=logging.INFO,
    protocol="HTTP",
    method="GET",
    url="http://example.com",
    headers={"User-Agent": "Mozilla/5.0"},
    client_ip="192.168.1.1",
    body=None
)
```

### Logging a Web Response

```python
from your_module import log_web_response

log_web_response(
    logger=logger,
    level=logging.INFO,
    protocol="HTTP",
    method="GET",
    url="http://example.com",
    status_code=200,
    response_time_ms=123,
    client_ip="192.168.1.1",
    headers={"Content-Type": "application/json"},
    body="Response content",
    event_reference_id="request-event-id"
)
```

### Logging Debug Information

```python
from your_module import log_debug

log_debug(
    logger=logger,
    level=logging.DEBUG,
    message="This is a debug message",
    additional_data={"key": "value"}
)
```

## Logger Components

### Classes

- `RequestResponseLogFormatter`: A custom formatter for structured logging.
- `Protocol` and `Method` Enums: Validates protocol and HTTP method values.

### Methods

#### `setup_logger`
Configures a logger for structured logging with RFC 5424 compliance.

#### `log_web_request`
Logs a structured `WebRequest` event.

#### `log_web_response`
Logs a structured `WebResponse` event with optional body and debug mode.

#### `log_debug`
Logs a debug-level event with additional structured data.

## Example Log Output

```json
{
  "EventType": "WebResponse",
  "EventID": "12345-abcde",
  "EventReferenceID": "67890-fghij",
  "EventData": {
    "Protocol": "HTTP",
    "Method": "GET",
    "Url": "http://example.com",
    "Headers": {
      "Content-Type": "application/json"
    },
    "Body": "Response content",
    "StatusCode": 200,
    "ResponseTimeMS": 123,
    "ClientIP": "192.168.1.1"
  }
}
```

## Error Handling

- Missing mandatory fields will raise a `ValueError`.
- Invalid protocol or method values will also raise a `ValueError`.
