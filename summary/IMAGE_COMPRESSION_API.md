# Image Compression API

This API provides image compression functionality using Sharp, designed to work with Cloudflare Pages where Sharp is not supported.

## API Endpoints

### 1. Compress Single JPG Image
**Endpoint:** `POST /api/compress/jpg`

**Description:** Compresses a single JPG/JPEG image with specified quality.

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Body:
  - `file` (required): JPG/JPEG image file
  - `quality` (optional): Compression quality 1-100 (default: 80)

**Response:**
- Content-Type: `image/jpeg`
- Headers:
  - `Content-Disposition`: attachment with compressed filename
  - `X-Original-Size`: Original file size in bytes
  - `X-Compressed-Size`: Compressed file size in bytes
  - `X-Compression-Ratio`: Compression ratio percentage
  - `X-Quality`: Quality used for compression
  - `X-Original-Filename`: Original filename

**Example using curl:**
```bash
curl -X POST http://localhost:3002/api/compress/jpg \
  -F "file=@image.jpg" \
  -F "quality=75" \
  --output compressed_image.jpg
```

### 2. Batch Compress Multiple Images
**Endpoint:** `POST /api/compress/batch`

**Description:** Compresses multiple JPG/JPEG images (max 10 files).

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Body:
  - `files` (required): Array of JPG/JPEG image files (max 10)
  - `quality` (optional): Compression quality 1-100 (default: 80)

**Response:**
- Content-Type: `application/json`
- Body:
```json
{
  "success": true,
  "message": "Batch compression completed",
  "data": {
    "results": [
      {
        "originalName": "image1.jpg",
        "compressedName": "image1_compressed.jpg",
        "originalSize": 1024000,
        "compressedSize": 512000,
        "compressionRatio": "50.0%",
        "compressedData": "base64-encoded-image-data"
      }
    ],
    "errors": [],
    "summary": {
      "totalFiles": 1,
      "successful": 1,
      "failed": 0,
      "quality": 80
    }
  }
}
```

### 3. Get API Information
**Endpoint:** `GET /api/compress/info`

**Description:** Returns information about the compression service.

**Response:**
```json
{
  "success": true,
  "message": "Compression service information",
  "data": {
    "service": "Image Compression API",
    "version": "1.0.0",
    "supportedFormats": ["image/jpeg", "image/jpg"],
    "limits": {
      "maxFileSize": "10MB",
      "maxBatchFiles": 10,
      "qualityRange": "1-100"
    },
    "features": {
      "autoRotation": true,
      "mozjpegEncoder": true,
      "chromaSubsampling": "4:2:0",
      "compressionStats": true,
      "batchProcessing": true
    }
  }
}
```

## Modified Next.js Code

### TypeScript Version (`modified-nextjs-code.ts`)
Use this version if your Next.js project uses TypeScript:

```typescript
import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const file = formData.get("file") as File;
    const quality = parseInt(formData.get("quality") as string) || 80;

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 });
    }

    // Check if file is JPG/JPEG
    if (!file.type.includes("jpeg") && !file.type.includes("jpg")) {
      return NextResponse.json(
        { error: "File must be a JPG/JPEG image" },
        { status: 400 }
      );
    }

    // Create FormData to send to your API
    const apiFormData = new FormData();
    apiFormData.append("file", file);
    apiFormData.append("quality", quality.toString());

    // Call your compression API
    const API_BASE_URL = process.env.COMPRESSION_API_URL || "http://localhost:3002";
    const response = await fetch(`${API_BASE_URL}/api/compress/jpg`, {
      method: "POST",
      body: apiFormData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return NextResponse.json(
        { 
          error: "Failed to compress image", 
          details: errorData.message || "Unknown error" 
        },
        { status: response.status }
      );
    }

    // Get the compressed image buffer
    const compressedBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(compressedBuffer);

    // Get compression stats from response headers
    const originalSize = parseInt(response.headers.get("X-Original-Size") || "0");
    const compressedSize = parseInt(response.headers.get("X-Compressed-Size") || "0");
    const compressionRatio = response.headers.get("X-Compression-Ratio") || "0";
    const originalFilename = response.headers.get("X-Original-Filename") || file.name;

    // Generate filename (same as original logic)
    const originalName = originalFilename.replace(/\.[^/.]+$/, "");
    const filename = `${originalName}_compressed.jpg`;

    return new NextResponse(buffer, {
      headers: {
        "Content-Type": "image/jpeg",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Content-Length": buffer.length.toString(),
        "X-Original-Size": originalSize.toString(),
        "X-Compressed-Size": compressedSize.toString(),
        "X-Compression-Ratio": compressionRatio,
      },
    });
  } catch (error) {
    console.error("Error compressing JPG:", error);
    return NextResponse.json(
      { error: "Failed to compress image" },
      { status: 500 }
    );
  }
}
```

### JavaScript Version (`modified-nextjs-code.js`)
Use this version if your Next.js project uses JavaScript:

```javascript
import { NextRequest, NextResponse } from "next/server";

export async function POST(request) {
  try {
    const formData = await request.formData();
    const file = formData.get("file");
    const quality = parseInt(formData.get("quality")) || 80;

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 });
    }

    // Check if file is JPG/JPEG
    if (!file.type.includes("jpeg") && !file.type.includes("jpg")) {
      return NextResponse.json(
        { error: "File must be a JPG/JPEG image" },
        { status: 400 }
      );
    }

    // Create FormData to send to your API
    const apiFormData = new FormData();
    apiFormData.append("file", file);
    apiFormData.append("quality", quality.toString());

    // Call your compression API
    const API_BASE_URL = process.env.COMPRESSION_API_URL || "http://localhost:3002";
    const response = await fetch(`${API_BASE_URL}/api/compress/jpg`, {
      method: "POST",
      body: apiFormData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return NextResponse.json(
        { 
          error: "Failed to compress image", 
          details: errorData.message || "Unknown error" 
        },
        { status: response.status }
      );
    }

    // Get the compressed image buffer
    const compressedBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(compressedBuffer);

    // Get compression stats from response headers
    const originalSize = parseInt(response.headers.get("X-Original-Size") || "0");
    const compressedSize = parseInt(response.headers.get("X-Compressed-Size") || "0");
    const compressionRatio = response.headers.get("X-Compression-Ratio") || "0";
    const originalFilename = response.headers.get("X-Original-Filename") || file.name;

    // Generate filename (same as original logic)
    const originalName = originalFilename.replace(/\.[^/.]+$/, "");
    const filename = `${originalName}_compressed.jpg`;

    return new NextResponse(buffer, {
      headers: {
        "Content-Type": "image/jpeg",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Content-Length": buffer.length.toString(),
        "X-Original-Size": originalSize.toString(),
        "X-Compressed-Size": compressedSize.toString(),
        "X-Compression-Ratio": compressionRatio,
      },
    });
  } catch (error) {
    console.error("Error compressing JPG:", error);
    return NextResponse.json(
      { error: "Failed to compress image" },
      { status: 500 }
    );
  }
}
```

## Environment Variables

Add this environment variable to your Next.js project:

```env
COMPRESSION_API_URL=https://your-api-domain.com
```

If not set, it defaults to `http://localhost:3002` for local development.

## Setup Instructions

### 1. Deploy the API
1. Deploy this Node.js API to your preferred hosting service (Railway, Render, DigitalOcean, etc.)
2. Make sure the API is accessible from your Next.js application
3. Note the API URL for configuration

### 2. Update Your Next.js Project
1. Replace your existing Sharp-based route handler with the modified code above
2. Set the `COMPRESSION_API_URL` environment variable to point to your deployed API
3. Deploy your Next.js project to Cloudflare Pages

### 3. Test the Integration
1. Upload a JPG image through your Next.js application
2. Verify that the image is compressed and returned with the same functionality as before
3. Check the compression statistics in the response headers

## Features

- **Sharp Integration**: Uses Sharp library for high-quality image compression
- **Auto-rotation**: Automatically rotates images based on EXIF orientation
- **MozJPEG Encoder**: Uses MozJPEG for better compression ratios
- **Compression Statistics**: Returns detailed compression information
- **Rate Limiting**: Built-in rate limiting for API protection
- **Error Handling**: Comprehensive error handling and logging
- **Batch Processing**: Support for compressing multiple images at once
- **Flexible Quality**: Configurable compression quality (1-100)

## Error Handling

The API returns appropriate HTTP status codes and error messages:

- `400 Bad Request`: Invalid file type, missing file, or invalid quality parameter
- `413 Payload Too Large`: File size exceeds 10MB limit
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side processing error

## Rate Limiting

The API includes rate limiting:
- 100 requests per 15-minute window per IP address
- Rate limit headers are included in responses
- Configurable through environment variables

## Security Features

- File type validation (only JPG/JPEG allowed)
- File size limits (10MB maximum)
- Rate limiting protection
- Input sanitization
- Comprehensive logging for monitoring
