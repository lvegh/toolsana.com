# Image to Text (OCR) API Documentation

## Overview

The Toolsana OCR API provides powerful image-to-text extraction capabilities using Tesseract.js with advanced image preprocessing. The API includes comprehensive security, rate limiting, and caching for optimal performance.

## Features

- **Advanced OCR**: Tesseract.js-powered text extraction
- **Image Preprocessing**: Automatic image enhancement for better accuracy
  - Grayscale conversion
  - Contrast enhancement
  - Sharpening
  - Thresholding
  - Denoising
  - Automatic resizing
- **Multi-Language Support**: 25+ languages supported
- **Caching**: Redis-based caching with 7-day TTL
- **Security**: Multiple security layers with rate limiting
- **Confidence Scores**: Per-block, line, and word confidence metrics
- **Bounding Boxes**: Precise text location information

## Endpoints

### 1. Extract Text from Image

**Endpoint**: `POST /api/ocr/image-to-text`

**Rate Limit**: 20 requests per hour per user

**Authentication**: Required (Bearer token or X-API-Key)

**Request Format**: `multipart/form-data`

**Parameters**:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image` | File | Yes | - | Image file (JPEG, PNG, WebP, TIFF, GIF, BMP, PDF) |
| `language` | String | No | `eng` | ISO 639-3 language code(s), e.g., "eng", "eng+fra" |
| `bypassCache` | Boolean | No | `false` | Bypass cache and force fresh OCR |
| `threshold` | Boolean | No | `true` | Apply threshold preprocessing |
| `thresholdValue` | Integer | No | `128` | Threshold value (0-255) |
| `denoise` | Boolean | No | `true` | Apply denoising |
| `maxDimension` | Integer | No | `3000` | Max dimension (500-5000) |

**Example Request**:

```bash
curl -X POST https://api.toolsana.com/api/image-to-text \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "image=@document.jpg" \
  -F "language=eng" \
  -F "threshold=true" \
  -F "denoise=true"
```

**Example Response**:

```json
{
  "success": true,
  "message": "Text extracted successfully",
  "data": {
    "text": "Extracted text content from the image...",
    "confidence": 92.5,
    "language": "eng",
    "processingTime": 3450,
    "cached": false,
    "metadata": {
      "originalName": "document.jpg",
      "fileSize": 524288,
      "mimeType": "image/jpeg",
      "blockCount": 12,
      "lineCount": 45,
      "wordCount": 234
    },
    "blocks": [
      {
        "text": "First paragraph text...",
        "confidence": 95.2,
        "bbox": {
          "x": 10,
          "y": 20,
          "width": 500,
          "height": 100
        }
      }
    ],
    "lines": [
      {
        "text": "First line of text",
        "confidence": 96.5,
        "bbox": {
          "x": 10,
          "y": 20,
          "width": 300,
          "height": 25
        },
        "baseline": {
          "x0": 10,
          "y0": 45,
          "x1": 310,
          "y1": 45,
          "has_baseline": true
        }
      }
    ],
    "words": [
      {
        "text": "First",
        "confidence": 98.1,
        "bbox": {
          "x": 10,
          "y": 20,
          "width": 50,
          "height": 25
        },
        "isNumeric": false,
        "isBold": false,
        "isItalic": false
      }
    ]
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

**Response Headers**:

- `X-Processing-Time`: Processing time in milliseconds
- `X-Cached`: Whether result was cached (`true`/`false`)
- `X-OCR-Language`: Language used for OCR
- `X-OCR-Confidence`: Overall confidence score
- `X-Text-Length`: Length of extracted text
- `X-Block-Count`: Number of text blocks detected

### 2. Validate Image

**Endpoint**: `POST /api/ocr/validate`

**Rate Limit**: 20 requests per hour per user

**Authentication**: Required

**Request Format**: `multipart/form-data`

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `image` | File | Yes | Image file to validate |

**Example Request**:

```bash
curl -X POST https://api.toolsana.com/api/ocr-validate \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "image=@test.png"
```

**Example Response**:

```json
{
  "success": true,
  "message": "Image is valid for OCR processing",
  "data": {
    "valid": true,
    "format": "png",
    "width": 1920,
    "height": 1080,
    "size": 524288,
    "originalName": "test.png"
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### 3. Get Supported Languages

**Endpoint**: `GET /api/ocr/languages`

**Rate Limit**: 20 requests per hour per user

**Authentication**: Not required

**Example Request**:

```bash
curl -X GET https://api.toolsana.com/api/ocr-languages
```

**Example Response**:

```json
{
  "success": true,
  "message": "Supported languages retrieved",
  "data": {
    "languages": [
      { "code": "eng", "name": "English" },
      { "code": "fra", "name": "French" },
      { "code": "deu", "name": "German" },
      { "code": "spa", "name": "Spanish" },
      { "code": "ita", "name": "Italian" }
    ],
    "count": 25,
    "multiLanguageSupport": true,
    "example": "eng+fra for English and French"
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### 4. Get OCR Service Info

**Endpoint**: `GET /api/ocr/info`

**Rate Limit**: 20 requests per hour per user

**Authentication**: Not required

**Example Request**:

```bash
curl -X GET https://api.toolsana.com/api/ocr-info
```

**Example Response**:

```json
{
  "success": true,
  "message": "OCR service information",
  "data": {
    "service": "OCR (Optical Character Recognition) Service",
    "version": "1.0.0",
    "provider": "Tesseract.js",
    "supportedLanguages": ["eng", "fra", "deu", "..."],
    "features": {
      "preprocessing": true,
      "caching": true,
      "multiLanguage": true,
      "blockDetection": true,
      "lineDetection": true,
      "wordDetection": true,
      "confidenceScores": true
    },
    "limits": {
      "maxFileSize": "10MB",
      "maxDimension": 3000,
      "cacheTTL": "7 days"
    },
    "preprocessing": {
      "grayscale": true,
      "contrast": true,
      "sharpening": true,
      "thresholding": true,
      "denoising": true,
      "resizing": true
    },
    "endpoints": {
      "imageToText": "POST /api/ocr/image-to-text",
      "validate": "POST /api/ocr/validate",
      "info": "GET /api/ocr/info"
    },
    "rateLimit": {
      "requests": 20,
      "window": "1 hour"
    }
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Supported Languages

The OCR API supports 25+ languages:

- English (eng)
- French (fra)
- German (deu)
- Spanish (spa)
- Italian (ita)
- Portuguese (por)
- Russian (rus)
- Arabic (ara)
- Chinese (zho)
- Japanese (jpn)
- Korean (kor)
- Hindi (hin)
- Bengali (ben)
- Turkish (tur)
- Vietnamese (vie)
- Thai (tha)
- Dutch (nld)
- Polish (pol)
- Swedish (swe)
- Norwegian (nor)
- Danish (dan)
- Finnish (fin)
- Czech (ces)
- Romanian (ron)
- Hungarian (hun)

**Multi-language OCR**: Combine languages with `+`, e.g., `eng+fra` for English and French.

## Supported File Formats

- **Images**: JPEG, JPG, PNG, WebP, TIFF, GIF, BMP
- **Documents**: PDF
- **Max File Size**: 10MB
- **Max Dimension**: 3000px (automatically resized if larger)

## Image Preprocessing

The OCR service automatically preprocesses images for optimal text recognition:

1. **Grayscale Conversion**: Converts to grayscale for better text detection
2. **Resize**: Automatically resizes large images (max 3000px)
3. **Normalize**: Enhances contrast using histogram equalization
4. **Sharpen**: Improves edge detection
5. **Threshold**: Binary threshold for clear text separation (optional)
6. **Denoise**: Median filter to remove noise (optional)

You can customize preprocessing parameters in the request.

## Caching

The OCR API uses Redis-based caching to improve performance:

- **Cache Key**: SHA256 hash of image buffer + language
- **TTL**: 7 days
- **Bypass**: Use `bypassCache=true` to force fresh OCR
- **Cache Headers**: `X-Cached` response header indicates cache status

## Rate Limiting

- **Limit**: 20 requests per hour per user
- **Identification**: IP address + User-Agent
- **Headers**: Rate limit info in response headers
- **429 Response**: Includes `retryAfter` (seconds)

**Rate Limit Response**:

```json
{
  "success": false,
  "message": "OCR rate limit exceeded. Maximum 20 requests per hour allowed.",
  "retryAfter": 3600,
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Security

The OCR API implements multiple security layers:

1. **Authentication**: Bearer token or API key required
2. **Rate Limiting**: Strict limits to prevent abuse
3. **Input Validation**: Comprehensive validation with express-validator
4. **XSS Protection**: Input sanitization
5. **File Validation**: Format and size checks
6. **Brute Force Protection**: IP-based blocking
7. **Security Logging**: All security events logged

## Error Handling

**Error Response Format**:

```json
{
  "success": false,
  "message": "Error description",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "errors": [
    {
      "field": "language",
      "message": "Invalid language code format",
      "value": "invalid"
    }
  ]
}
```

**Common Error Codes**:

- `400`: Bad Request (validation error, invalid file)
- `401`: Unauthorized (missing/invalid token)
- `413`: Payload Too Large (file exceeds 10MB)
- `429`: Too Many Requests (rate limit exceeded)
- `500`: Internal Server Error

## Best Practices

1. **Image Quality**: Use high-quality, clear images for best results
2. **File Format**: PNG or TIFF for documents, JPEG for photos
3. **Language**: Specify correct language(s) for better accuracy
4. **Preprocessing**: Use default preprocessing for most cases
5. **Caching**: Leverage caching for repeated OCR of same images
6. **Error Handling**: Always check `success` field and handle errors
7. **Rate Limits**: Monitor rate limit headers to avoid blocking

## Examples

### Node.js Example

```javascript
const FormData = require('form-data');
const fs = require('fs');
const fetch = require('node-fetch');

async function extractText(imagePath) {
  const formData = new FormData();
  formData.append('image', fs.createReadStream(imagePath));
  formData.append('language', 'eng');

  const response = await fetch('https://api.toolsana.com/api/image-to-text', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer YOUR_API_KEY',
    },
    body: formData
  });

  const result = await response.json();

  if (result.success) {
    console.log('Extracted text:', result.data.text);
    console.log('Confidence:', result.data.confidence);
    console.log('Processing time:', result.data.processingTime, 'ms');
  } else {
    console.error('OCR failed:', result.message);
  }
}

extractText('document.jpg');
```

### Python Example

```python
import requests

def extract_text(image_path):
    url = 'https://api.toolsana.com/api/image-to-text'

    headers = {
        'Authorization': 'Bearer YOUR_API_KEY'
    }

    files = {
        'image': open(image_path, 'rb')
    }

    data = {
        'language': 'eng',
        'threshold': 'true',
        'denoise': 'true'
    }

    response = requests.post(url, headers=headers, files=files, data=data)
    result = response.json()

    if result['success']:
        print('Extracted text:', result['data']['text'])
        print('Confidence:', result['data']['confidence'])
        print('Processing time:', result['data']['processingTime'], 'ms')
    else:
        print('OCR failed:', result['message'])

extract_text('document.jpg')
```

### cURL Example

```bash
# Extract text from image
curl -X POST https://api.toolsana.com/api/image-to-text \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "image=@document.jpg" \
  -F "language=eng" \
  -F "threshold=true"

# Validate image
curl -X POST https://api.toolsana.com/api/ocr-validate \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "image=@test.png"

# Get supported languages
curl -X GET https://api.toolsana.com/api/ocr-languages

# Get service info
curl -X GET https://api.toolsana.com/api/ocr-info
```

## Cloudflare Worker Endpoints

The OCR API is also available through Cloudflare Workers at:

- `POST /api/image-to-text` → `/api/ocr/image-to-text`
- `POST /api/ocr-validate` → `/api/ocr/validate`
- `GET /api/ocr-info` → `/api/ocr/info`
- `GET /api/ocr-languages` → `/api/ocr/languages`

## Performance

- **Average OCR Time**: 2-4 seconds (depends on image size and complexity)
- **Cache Hit Time**: <100ms
- **Max Concurrent Requests**: 10 per server instance
- **Image Preprocessing**: 500-1000ms (automatic)

## Support

For support, bug reports, or feature requests:

- **Email**: info@toolsana.com
- **GitHub**: https://github.com/toolsana/api
- **Documentation**: https://docs.toolsana.com

## License

MIT License - See LICENSE file for details
